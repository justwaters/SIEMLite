// Package mcp is a small Model Context Protocol server: JSON-RPC 2.0 over the
// "streamable HTTP" transport, answering each POST with one JSON body. It lets
// an AI agent list and call a set of tools, and it knows nothing about what the
// tools do: the caller gives it the tools and the access level of whoever is
// asking, and it hides and refuses what that level may not use.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Levels, lowest first. A caller may use the tools whose Min is at most its level.
const (
	LevelRead = iota
	LevelAnalyst
	LevelAdmin
)

var levelNames = []string{"read-only", "analyst", "admin"}

// versions the server speaks, newest first.
var versions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// maxResultBytes keeps one answer from filling an agent's context.
const maxResultBytes = 200_000

// Result is what a tool returns: text for the model, and whether it is an error
// (a mistake the model can read and correct, not a failure of the protocol).
type Result struct {
	Text    string
	IsError bool
}

// Tool is one thing an agent can do.
type Tool struct {
	Name        string
	Description string
	// Schema is the JSON Schema of the arguments (an object).
	Schema      map[string]any
	Min         int  // the lowest level that may use it
	ReadOnly    bool // changes nothing
	Destructive bool // may delete or overwrite
	Run         func(ctx context.Context, args json.RawMessage) (Result, error)
}

// Server answers MCP requests for a set of tools.
type Server struct {
	Name         string
	Version      string
	Instructions string
	Tools        []Tool
	// OnCall, if set, is told about every tool call: the tool, the arguments,
	// and the result. A call the token's level refuses is reported too, with
	// denied set.
	OnCall func(ctx context.Context, t Tool, args json.RawMessage, res Result, denied bool)
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	// A client's answer to a request of ours has no method.
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Handle answers the body of one POST for a caller at level. It returns the
// HTTP status and the body (empty for a 202, when there is nothing to say back).
func (s *Server) Handle(ctx context.Context, level int, body []byte) (int, []byte) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return http.StatusBadRequest, marshal(errorResponse(nil, -32700, "empty request"))
	}
	if body[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(body, &batch); err != nil {
			return http.StatusBadRequest, marshal(errorResponse(nil, -32700, "parse error"))
		}
		if len(batch) == 0 {
			return http.StatusBadRequest, marshal(errorResponse(nil, -32600, "empty batch"))
		}
		var out []response
		for _, raw := range batch {
			if r, ok := s.handleOne(ctx, level, raw); ok {
				out = append(out, r)
			}
		}
		if len(out) == 0 {
			return http.StatusAccepted, nil
		}
		return http.StatusOK, marshal(out)
	}
	r, ok := s.handleOne(ctx, level, body)
	if !ok {
		return http.StatusAccepted, nil
	}
	if r.Error != nil && r.Error.Code == -32700 { // not JSON at all
		return http.StatusBadRequest, marshal(r)
	}
	return http.StatusOK, marshal(r)
}

func marshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}`)
	}
	return b
}

func errorResponse(id json.RawMessage, code int, msg string) response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// handleOne answers one JSON-RPC message; ok is false for a notification or a
// reply, which get no answer.
func (s *Server) handleOne(ctx context.Context, level int, raw []byte) (response, bool) {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return errorResponse(nil, -32700, "parse error"), true
	}
	if req.Method == "" { // a reply to us (we send no requests), or not a request at all
		if len(req.Result) > 0 || len(req.Error) > 0 {
			return response{}, false
		}
		return errorResponse(req.ID, -32600, "invalid request"), true
	}
	if len(req.ID) == 0 { // a notification
		return response{}, false
	}
	ok := func(v any) (response, bool) { return response{JSONRPC: "2.0", ID: req.ID, Result: v}, true }
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := versions[0]
		for _, v := range versions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		res := map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
		}
		if s.Instructions != "" {
			res["instructions"] = s.Instructions
		}
		return ok(res)
	case "ping":
		return ok(map[string]any{})
	case "tools/list":
		tools := []map[string]any{}
		for _, t := range s.Tools {
			if t.Min > level {
				continue
			}
			tools = append(tools, map[string]any{
				"name": t.Name, "description": t.Description, "inputSchema": t.Schema,
				"annotations": map[string]any{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Destructive && !t.ReadOnly, "openWorldHint": false},
			})
		}
		return ok(map[string]any{"tools": tools})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return errorResponse(req.ID, -32602, "tools/call needs a tool name"), true
		}
		for _, t := range s.Tools {
			if t.Name != p.Name {
				continue
			}
			if t.Min > level {
				if s.OnCall != nil {
					s.OnCall(ctx, t, p.Arguments, Result{IsError: true}, true)
				}
				return ok(textResult(Result{IsError: true, Text: fmt.Sprintf("This token is %s and can't use %s. It needs a token with the %s level; an admin can make one on the Integrations page.",
					levelNames[level], t.Name, levelNames[t.Min])}))
			}
			if len(bytes.TrimSpace(p.Arguments)) == 0 {
				p.Arguments = json.RawMessage("{}")
			}
			res := s.run(ctx, t, p.Arguments)
			if s.OnCall != nil {
				s.OnCall(ctx, t, p.Arguments, res, false)
			}
			return ok(textResult(res))
		}
		return errorResponse(req.ID, -32602, "unknown tool: "+p.Name), true
	}
	return errorResponse(req.ID, -32601, "method not found: "+req.Method), true
}

// run calls a tool, turning its error or a panic into text the model can read.
func (s *Server) run(ctx context.Context, t Tool, args json.RawMessage) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res = Result{IsError: true, Text: "The tool failed unexpectedly."}
		}
	}()
	res, err := t.Run(ctx, args)
	if err != nil {
		return Result{IsError: true, Text: err.Error()}
	}
	return res
}

func textResult(r Result) map[string]any {
	text := r.Text
	if len(text) > maxResultBytes {
		cut := text[:maxResultBytes]
		if i := strings.LastIndexByte(cut, '\n'); i > maxResultBytes/2 {
			cut = cut[:i]
		}
		text = cut + "\n… [the answer was cut at 200 KB; narrow the search or use a smaller limit]"
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": r.IsError}
}
