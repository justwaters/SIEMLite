package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A free model has no company that meets SIEMLite's data rule; the user is told what to do, not just OpenRouter's words.
func TestOpenRouterDataPolicyErrorIsExplained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"message":"No endpoints found matching your data policy (Free model training). Configure: https://openrouter.ai/settings/privacy"}}`))
	}))
	defer srv.Close()
	o := &openRouter{base: srv.URL, key: "k", model: "vendor/some-model:free", http: srv.Client()}
	_, err := o.chat(context.Background(), []map[string]string{{"role": "user", "content": "x"}}, map[string]any{})
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"vendor/some-model:free", "Pick a model that isn't free", "No endpoints found"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

// Allowing free models lifts the refusal of data-keeping companies for ":free" models only.
func TestOpenRouterAllowFree(t *testing.T) {
	for _, c := range []struct {
		model string
		allow bool
		want  string
	}{
		{"vendor/m:free", false, "deny"},
		{"vendor/m:free", true, "allow"},
		{"vendor/m", true, "deny"},
		{"vendor/m", false, "deny"},
		{"~anthropic/claude-haiku-latest", true, "deny"},
	} {
		o := &openRouter{model: c.model, allowFree: c.allow}
		if got := o.dataCollection(); got != c.want {
			t.Errorf("%s allow=%v: %s, want %s", c.model, c.allow, got, c.want)
		}
	}
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<16)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
		w.Write([]byte(`{"choices":[{"message":{"content":"{}"}}]}`))
	}))
	defer srv.Close()
	o := &openRouter{base: srv.URL, key: "k", model: "vendor/m:free", http: srv.Client(), allowFree: true}
	if _, err := o.chat(context.Background(), []map[string]string{{"role": "user", "content": "x"}}, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"data_collection":"allow"`) || !strings.Contains(body, `"require_parameters":true`) {
		t.Errorf("request = %s", body)
	}
}
