package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// chatter is a model that answers a conversation with JSON in a given shape.
type chatter interface {
	chat(ctx context.Context, msgs []map[string]string, schema any) (string, error)
}

// --- Ollama, on this server ---

type ollama struct {
	url, model string
	http       *http.Client
}

func newOllama(url, model string) *ollama {
	return &ollama{url: strings.TrimRight(url, "/"), model: model, http: &http.Client{Timeout: 5 * time.Minute, Transport: ollamaTransport, CheckRedirect: noRedirects}}
}

// ollamaTransport won't connect to link-local or cloud metadata addresses,
// whatever name leads there: an Ollama address is never one, and a request
// there could read the server's cloud credentials. Redirects aren't followed.
var ollamaTransport = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		a, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		if forbiddenAddr(a.Unmap()) {
			return fmt.Errorf("%s is a link-local or cloud metadata address, which can't be an Ollama server", a)
		}
		return nil
	}}).DialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 5 * time.Minute,
}

// Ollama never redirects; following one could lead anywhere.
func noRedirects(*http.Request, []*http.Request) error {
	return errors.New("Ollama doesn't redirect, so this isn't Ollama")
}

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func forbiddenAddr(a netip.Addr) bool {
	if nat64.Contains(a) { // an IPv4 address reached through NAT64
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	a = a.Unmap()
	return a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() ||
		(a.Is4() && a.As4()[0] == 0) ||
		a == netip.MustParseAddr("100.100.100.200") || a == netip.MustParseAddr("fd00:ec2::254")
}

// CheckOllamaURL is the one check for an Ollama address, wherever it is used.
func CheckOllamaURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the Ollama address must be an http or https address with no path, such as http://ollama:11434")
	}
	if a, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && forbiddenAddr(a.Unmap()) {
		return errors.New("the Ollama address can't be a link-local or cloud metadata address")
	}
	return nil
}

// ollamaError says what went wrong without repeating anything the far end
// sent, since the address might lead somewhere that isn't Ollama.
func ollamaError(path string, code int) error {
	switch code {
	case http.StatusNotFound:
		if path == "/api/tags" {
			return fmt.Errorf("ollama %s: not found, so this isn't an Ollama server", path)
		}
		return fmt.Errorf("ollama %s: not found (is the model name right?)", path)
	}
	return fmt.Errorf("ollama %s: %d %s", path, code, http.StatusText(code))
}

func (o *ollama) chat(ctx context.Context, msgs []map[string]string, schema any) (string, error) {
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	err := o.call(ctx, http.MethodPost, "/api/chat", map[string]any{
		"model": o.model, "messages": msgs, "stream": false, "format": schema,
		"options": map[string]any{"temperature": 0.1},
	}, &out)
	return out.Message.Content, err
}

// LocalModel is a model Ollama has downloaded.
type LocalModel struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// models lists what Ollama has downloaded.
func (o *ollama) models(ctx context.Context) ([]LocalModel, error) {
	var tags struct {
		Models []LocalModel `json:"models"`
	}
	err := o.call(ctx, http.MethodGet, "/api/tags", nil, &tags)
	return tags.Models, err
}

// usingGPU reports whether a loaded model sits (partly) in GPU memory, which
// Ollama only knows once a model has run.
func (o *ollama) usingGPU(ctx context.Context) bool {
	var ps struct {
		Models []struct {
			SizeVRAM int64 `json:"size_vram"`
		} `json:"models"`
	}
	if o.call(ctx, http.MethodGet, "/api/ps", nil, &ps) != nil {
		return false
	}
	for _, m := range ps.Models {
		if m.SizeVRAM > 0 {
			return true
		}
	}
	return false
}

func hasModel(models []LocalModel, name string) bool {
	for _, m := range models {
		if m.Name == name || m.Name == name+":latest" {
			return true
		}
	}
	return false
}

// pull downloads a model, reporting progress, until it is done or fails.
func (o *ollama) pull(ctx context.Context, progress func(status string, done, total int64)) error {
	body, _ := json.Marshal(map[string]any{"model": o.model, "stream": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url+"/api/pull", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: ollamaTransport, CheckRedirect: noRedirects}).Do(req) // no timeout: downloads take minutes
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ollamaError("/api/pull", resp.StatusCode)
	}
	last := ""
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var st struct {
			Status    string `json:"status"`
			Error     string `json:"error"`
			Total     int64  `json:"total"`
			Completed int64  `json:"completed"`
		}
		if json.Unmarshal(sc.Bytes(), &st) != nil {
			continue
		}
		if st.Error != "" {
			if len(st.Error) > 200 {
				st.Error = st.Error[:200]
			}
			return errors.New(st.Error)
		}
		last = st.Status
		progress(st.Status, st.Completed, st.Total)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if last != "success" {
		return fmt.Errorf("the download ended with %q", last)
	}
	return nil
}

func (o *ollama) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, o.url+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return ollamaError(path, resp.StatusCode)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("ollama %s: the answer isn't from Ollama", path)
	}
	return nil
}

// --- OpenRouter, in the cloud ---

// DefaultOpenRouter is OpenRouter's API.
const DefaultOpenRouter = "https://openrouter.ai/api/v1"

type openRouter struct {
	base, key, model string
	http             *http.Client
	allowFree        bool // a ":free" model may go to companies that keep what is sent
}

// dataCollection is what OpenRouter is told about companies that keep or train on what they are sent.
func (o *openRouter) dataCollection() string {
	if o.allowFree && strings.HasSuffix(o.model, ":free") {
		return "allow"
	}
	return "deny"
}

func (o *openRouter) chat(ctx context.Context, msgs []map[string]string, schema any) (string, error) {
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	err := o.call(ctx, http.MethodPost, "/chat/completions", map[string]any{
		"model": o.model, "messages": msgs, "temperature": 0.1,
		"response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "parser", "schema": schema}},
		// Only providers that honour the JSON shape, and none that keep what is sent.
		"provider": map[string]any{"require_parameters": true, "data_collection": o.dataCollection()},
	}, &out)
	if err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", errors.New("OpenRouter returned no answer")
	}
	return stripFence(out.Choices[0].Message.Content), nil
}

// stripFence removes a ```json fence some models put around JSON.
func stripFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

// keyInfo checks a key and says what OpenRouter knows about it.
func (o *openRouter) keyInfo(ctx context.Context) (label string, limitLeft *float64, err error) {
	var out struct {
		Data struct {
			Label          string   `json:"label"`
			LimitRemaining *float64 `json:"limit_remaining"`
		} `json:"data"`
	}
	if err := o.call(ctx, http.MethodGet, "/key", nil, &out); err != nil {
		return "", nil, err
	}
	return out.Data.Label, out.Data.LimitRemaining, nil
}

func (o *openRouter) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, o.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.key)
	req.Header.Set("X-Title", "SIEMLite")
	resp, err := o.http.Do(req)
	if err != nil {
		return fmt.Errorf("couldn't reach OpenRouter: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		msg := resp.Status
		if json.Unmarshal(b, &e) == nil && e.Error.Message != "" {
			msg = e.Error.Message
		}
		if strings.Contains(strings.ToLower(msg), "data policy") {
			return errors.New("OpenRouter has no company that can run " + o.model + " under SIEMLite's rule of only using " +
				"companies that don't keep or train on what they are sent. Free models usually run only on companies that do. " +
				"Pick a model that isn't free, or allow free models under Integrations > AI Parsers. (OpenRouter said: " + msg + ")")
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return errors.New("OpenRouter refused the API key: " + msg)
		case http.StatusPaymentRequired:
			return errors.New("the OpenRouter account is out of credit: " + msg)
		}
		return errors.New("OpenRouter: " + msg)
	}
	return json.Unmarshal(b, out)
}

// CloudModel is a model OpenRouter offers that can answer in a JSON shape.
type CloudModel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Prompt  string `json:"prompt_price"`     // US dollars per million input tokens
	Output  string `json:"completion_price"` // per million output tokens
	Free    bool   `json:"free,omitempty"`
	Context int    `json:"context_length"`
}

// cloudModels fetches OpenRouter's list (no key needed) and keeps the models
// that can answer in a given JSON shape.
func cloudModels(ctx context.Context, client *http.Client, base string) ([]CloudModel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/models", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't reach OpenRouter: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("OpenRouter's model list: " + resp.Status)
	}
	var out struct {
		Data []struct {
			ID      string   `json:"id"`
			Name    string   `json:"name"`
			Context int      `json:"context_length"`
			Params  []string `json:"supported_parameters"`
			Pricing struct {
				Prompt     string `json:"prompt"`
				Completion string `json:"completion"`
			} `json:"pricing"`
			Arch struct {
				Output []string `json:"output_modalities"`
			} `json:"architecture"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("OpenRouter's model list: %w", err)
	}
	var models []CloudModel
	for _, m := range out.Data {
		structured := false
		for _, p := range m.Params {
			if p == "structured_outputs" {
				structured = true
			}
		}
		text := len(m.Arch.Output) == 0
		for _, o := range m.Arch.Output {
			text = text || o == "text"
		}
		if !structured || !text || strings.HasSuffix(m.ID, ":batch") {
			continue
		}
		models = append(models, CloudModel{ID: m.ID, Name: m.Name, Context: m.Context,
			Prompt: perMillion(m.Pricing.Prompt), Output: perMillion(m.Pricing.Completion),
			Free: m.Pricing.Prompt == "0" && m.Pricing.Completion == "0"})
	}
	return models, nil
}

// perMillion turns a price per token ("0.00000015") into one per million tokens ("0.15").
func perMillion(perToken string) string {
	var f float64
	if _, err := fmt.Sscan(perToken, &f); err != nil || f < 0 {
		return ""
	}
	s := fmt.Sprintf("%.3f", f*1e6)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	return s
}
