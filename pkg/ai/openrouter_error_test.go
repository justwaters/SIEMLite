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
