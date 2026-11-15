package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Cloud services that can run the model, besides a model on this server.
// Each has its own key and model, kept when another one is chosen.

// CloudService describes one for the Integrations card.
type CloudService struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	KeyURL  string `json:"key_url"` // where to create an API key
	Privacy string `json:"privacy"` // what happens to what is sent, in a sentence
	base    string
	// recommend picks the suggested models from the service's list: the
	// newest model whose ID contains each of these, in order.
	recommend []string
	// fallback are suggested when the list can't be read.
	fallback []string
	// Suggested are the fallbacks, for the card to offer before the list is read.
	Suggested []string `json:"suggested"`
}

func init() {
	for i := range CloudServices {
		CloudServices[i].Suggested = CloudServices[i].fallback
	}
}

// The ID of a service is its value of Settings.Provider.
const (
	ProviderAnthropic = "anthropic"
	ProviderGoogle    = "google"
	ProviderOpenAI    = "openai"
	ProviderNVIDIA    = "nvidia"
)

// CloudServices are the services, in the order the card lists them.
var CloudServices = []CloudService{
	{ID: ProviderCloud, Name: "OpenRouter", KeyURL: "https://openrouter.ai/keys", base: DefaultOpenRouter,
		Privacy:  "OpenRouter passes the lines to the company that runs the model; SIEMLite asks only for companies that don't keep or train on them.",
		fallback: RecommendedCloud},
	{ID: ProviderAnthropic, Name: "Anthropic", KeyURL: "https://console.anthropic.com/settings/keys", base: "https://api.anthropic.com/v1",
		Privacy:   "Anthropic doesn't train on what is sent through its API, and keeps it only for a limited time.",
		recommend: []string{"haiku", "sonnet"}, fallback: []string{"claude-haiku-4-5"}},
	{ID: ProviderGoogle, Name: "Google Gemini", KeyURL: "https://aistudio.google.com/apikey", base: "https://generativelanguage.googleapis.com/v1beta",
		Privacy:   "With a free Gemini key, Google may use what is sent to improve its products; a key on a paid (billing) project doesn't.",
		recommend: []string{"flash-lite", "flash", "pro"}, fallback: []string{"gemini-2.5-flash"}},
	{ID: ProviderOpenAI, Name: "OpenAI", KeyURL: "https://platform.openai.com/api-keys", base: "https://api.openai.com/v1",
		Privacy:   "OpenAI doesn't train on what is sent through its API, and keeps it only for a limited time.",
		recommend: []string{"mini", "nano"}, fallback: []string{"gpt-4.1-mini"}},
	{ID: ProviderNVIDIA, Name: "NVIDIA", KeyURL: "https://build.nvidia.com/settings/api-keys", base: "https://integrate.api.nvidia.com/v1",
		Privacy:   "NVIDIA's hosted models (build.nvidia.com) run what is sent under NVIDIA's API terms.",
		recommend: []string{"llama-3.3-70b", "nemotron", "qwen"}, fallback: []string{"meta/llama-3.3-70b-instruct"}},
}

func cloudService(id string) (CloudService, bool) {
	for _, c := range CloudServices {
		if c.ID == id {
			return c, true
		}
	}
	return CloudService{}, false
}

// IsCloud reports whether a provider runs the model in the cloud.
func IsCloud(provider string) bool { _, ok := cloudService(provider); return ok }

// cloudError turns a service's error answer into a message for the person.
func cloudError(service string, status int, body []byte) error {
	var e struct {
		Error any `json:"error"`
	}
	msg := http.StatusText(status)
	if json.Unmarshal(body, &e) == nil {
		switch v := e.Error.(type) {
		case string:
			msg = v
		case map[string]any:
			if m, ok := v["message"].(string); ok && m != "" {
				msg = m
			}
		}
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%s refused the API key: %s", service, msg)
	case http.StatusPaymentRequired:
		return fmt.Errorf("the %s account is out of credit: %s", service, msg)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%s says too many requests, or the quota is used up: %s", service, msg)
	}
	return &serviceError{service: service, status: status, msg: msg}
}

type serviceError struct {
	service string
	status  int
	msg     string
}

func (e *serviceError) Error() string { return e.service + ": " + e.msg }

// send makes a JSON request and decodes the answer.
func send(ctx context.Context, client *http.Client, service, method, url string, headers map[string]string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("couldn't reach %s: %w", service, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return cloudError(service, resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s's answer couldn't be read: %w", service, err)
	}
	return nil
}

// noTemperature remembers the provider+model pairs that refused a
// temperature setting, so later calls leave it out. In memory only.
var noTemperature sync.Map

const requestTemperature = 0.1

// temperatureRejected reports whether an error is a 400 that complains about
// the temperature parameter (unsupported, deprecated, only the default allowed).
func temperatureRejected(err error) bool {
	var se *serviceError
	return errors.As(err, &se) && se.status == http.StatusBadRequest &&
		strings.Contains(strings.ToLower(se.msg), "temperature")
}

// sendWithTemperature sends the body build(true) makes, which carries a
// temperature; when the service refuses that setting it asks once more with
// build(false), and remembers the refusal for this service and model.
func sendWithTemperature(ctx context.Context, client *http.Client, service, model, method, url string, headers map[string]string, build func(withTemperature bool) any, out any) error {
	key := service + "|" + model
	if _, skip := noTemperature.Load(key); skip {
		return send(ctx, client, service, method, url, headers, build(false), out)
	}
	err := send(ctx, client, service, method, url, headers, build(true), out)
	if temperatureRejected(err) {
		noTemperature.Store(key, true)
		return send(ctx, client, service, method, url, headers, build(false), out)
	}
	return err
}

// --- OpenAI's API, and NVIDIA's, which follows it ---

type openAICompat struct {
	service, base, key, model string
	http                      *http.Client
}

// chat asks for the JSON shape; a model that won't take a schema is asked
// for any JSON, then plainly (the prompt describes the shape too).
func (o *openAICompat) chat(ctx context.Context, msgs []map[string]string, schema any) (string, error) {
	formats := []any{
		map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "parser", "schema": schema}},
		map[string]any{"type": "json_object"},
		nil,
	}
	var last error
	for _, f := range formats {
		build := func(withTemp bool) any {
			body := map[string]any{"model": o.model, "messages": msgs}
			if withTemp {
				body["temperature"] = requestTemperature
			}
			if f != nil {
				body["response_format"] = f
			}
			return body
		}
		var out struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		err := sendWithTemperature(ctx, o.http, o.service, o.model, http.MethodPost, o.base+"/chat/completions", map[string]string{"Authorization": "Bearer " + o.key}, build, &out)
		var se *serviceError
		if errors.As(err, &se) && se.status == http.StatusBadRequest {
			last = err
			continue // try a plainer request
		}
		if err != nil {
			return "", err
		}
		if len(out.Choices) == 0 {
			return "", fmt.Errorf("%s returned no answer", o.service)
		}
		return stripFence(out.Choices[0].Message.Content), nil
	}
	return "", last
}

// --- Anthropic ---

type anthropic struct {
	base, key, model string
	http             *http.Client
}

func (a *anthropic) headers() map[string]string {
	return map[string]string{"x-api-key": a.key, "anthropic-version": "2023-06-01"}
}

// chat asks for the JSON shape by giving Claude one tool whose input is that
// shape, and requiring it to be used.
func (a *anthropic) chat(ctx context.Context, msgs []map[string]string, schema any) (string, error) {
	var system []string
	var conv []map[string]string
	for _, m := range msgs {
		if m["role"] == "system" {
			system = append(system, m["content"])
			continue
		}
		conv = append(conv, map[string]string{"role": m["role"], "content": m["content"]})
	}
	build := func(withTemp bool) any {
		body := map[string]any{
			"model": a.model, "max_tokens": 4096, "messages": conv,
			"system":      strings.Join(system, "\n\n"),
			"tools":       []map[string]any{{"name": "parser", "description": "The answer, as a parser definition.", "input_schema": schema}},
			"tool_choice": map[string]any{"type": "tool", "name": "parser"},
		}
		if withTemp {
			body["temperature"] = requestTemperature
		}
		return body
	}
	var out struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := sendWithTemperature(ctx, a.http, "Anthropic", a.model, http.MethodPost, a.base+"/messages", a.headers(), build, &out); err != nil {
		return "", err
	}
	for _, c := range out.Content {
		if c.Type == "tool_use" && len(c.Input) > 0 {
			return string(c.Input), nil
		}
	}
	for _, c := range out.Content {
		if c.Type == "text" && strings.TrimSpace(c.Text) != "" {
			return stripFence(c.Text), nil
		}
	}
	return "", errors.New("Anthropic returned no answer")
}

// --- Google Gemini ---

type gemini struct {
	base, key, model string
	http             *http.Client
}

func (g *gemini) chat(ctx context.Context, msgs []map[string]string, schema any) (string, error) {
	var system []string
	var contents []map[string]any
	for _, m := range msgs {
		switch m["role"] {
		case "system":
			system = append(system, m["content"])
		case "assistant":
			contents = append(contents, map[string]any{"role": "model", "parts": []map[string]string{{"text": m["content"]}}})
		default:
			contents = append(contents, map[string]any{"role": "user", "parts": []map[string]string{{"text": m["content"]}}})
		}
	}
	for _, withSchema := range []bool{true, false} {
		build := func(withTemp bool) any {
			config := map[string]any{"responseMimeType": "application/json"}
			if withTemp {
				config["temperature"] = requestTemperature
			}
			if withSchema {
				config["responseJsonSchema"] = schema
			}
			body := map[string]any{"contents": contents, "generationConfig": config}
			if len(system) > 0 {
				body["systemInstruction"] = map[string]any{"parts": []map[string]string{{"text": strings.Join(system, "\n\n")}}}
			}
			return body
		}
		var out struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		err := sendWithTemperature(ctx, g.http, "Google Gemini", g.model, http.MethodPost, g.base+"/models/"+url.PathEscape(g.model)+":generateContent",
			map[string]string{"x-goog-api-key": g.key}, build, &out)
		var se *serviceError
		if withSchema && errors.As(err, &se) && se.status == http.StatusBadRequest {
			continue // a model that won't take the schema still answers in JSON
		}
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, c := range out.Candidates {
			for _, p := range c.Content.Parts {
				b.WriteString(p.Text)
			}
			break
		}
		if b.Len() == 0 {
			return "", errors.New("Google Gemini returned no answer")
		}
		return stripFence(b.String()), nil
	}
	return "", errors.New("Google Gemini returned no answer")
}

// --- Model lists ---

// listModels reads a service's models that can write text. OpenRouter's list
// is public and has prices; the others need the key.
func listModels(ctx context.Context, client *http.Client, svc CloudService, base, key string) ([]CloudModel, error) {
	var models []CloudModel
	switch svc.ID {
	case ProviderCloud:
		return cloudModels(ctx, client, base)
	case ProviderAnthropic:
		var out struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"display_name"`
			} `json:"data"`
		}
		a := &anthropic{key: key}
		if err := send(ctx, client, svc.Name, http.MethodGet, base+"/models?limit=1000", a.headers(), nil, &out); err != nil {
			return nil, err
		}
		for _, m := range out.Data {
			models = append(models, CloudModel{ID: m.ID, Name: m.Name})
		}
	case ProviderGoogle:
		var out struct {
			Models []struct {
				Name    string   `json:"name"`
				Display string   `json:"displayName"`
				Methods []string `json:"supportedGenerationMethods"`
			} `json:"models"`
		}
		if err := send(ctx, client, svc.Name, http.MethodGet, base+"/models?pageSize=1000", map[string]string{"x-goog-api-key": key}, nil, &out); err != nil {
			return nil, err
		}
		for _, m := range out.Models {
			id := strings.TrimPrefix(m.Name, "models/")
			if !contains(m.Methods, "generateContent") || hasAny(id, "embedding", "aqa", "imagen", "image", "tts", "audio", "veo") {
				continue
			}
			models = append(models, CloudModel{ID: id, Name: m.Display})
		}
	case ProviderOpenAI, ProviderNVIDIA:
		var out struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := send(ctx, client, svc.Name, http.MethodGet, base+"/models", map[string]string{"Authorization": "Bearer " + key}, nil, &out); err != nil {
			return nil, err
		}
		for _, m := range out.Data {
			if hasAny(m.ID, "embed", "rerank", "audio", "realtime", "tts", "transcribe", "whisper", "dall-e", "image", "moderation",
				"search", "guard", "reward", "parse", "vision", "babbage", "davinci", "codex") {
				continue
			}
			if svc.ID == ProviderOpenAI && !(strings.HasPrefix(m.ID, "gpt-") || strings.HasPrefix(m.ID, "o") || strings.HasPrefix(m.ID, "chatgpt")) {
				continue
			}
			models = append(models, CloudModel{ID: m.ID, Name: m.ID})
		}
	default:
		return nil, fmt.Errorf("no such service %q", svc.ID)
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ID > models[j].ID }) // newer versions sort first
	return models, nil
}

// recommended picks the suggested models from a list, or the fallbacks.
func recommended(svc CloudService, models []CloudModel) []string {
	if svc.ID == ProviderCloud || len(models) == 0 {
		return svc.fallback
	}
	var out []string
	for _, want := range svc.recommend {
		for _, m := range models {
			if strings.Contains(strings.ToLower(m.ID), want) && !contains(out, m.ID) && !hasAny(m.ID, "preview", "exp", "latest-") {
				out = append(out, m.ID)
				break
			}
		}
	}
	if len(out) == 0 {
		return svc.fallback
	}
	return out
}

func hasAny(s string, parts ...string) bool {
	s = strings.ToLower(s)
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
