package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestTemperatureRefusedIsRetriedAndRemembered: a model that answers 400 about
// temperature is asked again without it, and later calls leave it out.
func TestTemperatureRefusedIsRetriedAndRemembered(t *testing.T) {
	var mu sync.Mutex
	var sent []bool // whether each request carried a temperature
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		_, has := b["temperature"]
		mu.Lock()
		sent = append(sent, has)
		mu.Unlock()
		if has {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"message":"Unsupported value: 'temperature' does not support 0.1 with this model. Only the default (1) value is supported."}}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": parserAnswer}}}})
	}))
	defer srv.Close()
	noTemperature.Delete("TestSvc|reasoner")
	o := &openAICompat{service: "TestSvc", base: srv.URL, key: "k", model: "reasoner", http: http.DefaultClient}
	msgs := []map[string]string{{"role": "user", "content": "x"}}
	for i := 0; i < 2; i++ {
		out, err := o.chat(context.Background(), msgs, map[string]any{"type": "object"})
		if err != nil || out != parserAnswer {
			t.Fatalf("call %d = %q, %v", i, out, err)
		}
	}
	want := []bool{true, false, false}
	if len(sent) != len(want) {
		t.Fatalf("requests with temperature = %v, want %v", sent, want)
	}
	for i := range want {
		if sent[i] != want[i] {
			t.Fatalf("requests with temperature = %v, want %v", sent, want)
		}
	}
	// Another model of the same service is still asked with it.
	if _, skip := noTemperature.Load("TestSvc|other"); skip {
		t.Error("refusal leaked to another model")
	}
}

func TestOtherBadRequestsAreNotTemperature(t *testing.T) {
	if temperatureRejected(&serviceError{status: 400, msg: "response_format is not supported"}) {
		t.Error("unrelated 400 treated as a temperature refusal")
	}
	if !temperatureRejected(&serviceError{status: 400, msg: "`temperature` is deprecated for this model"}) {
		t.Error("temperature 400 not recognised")
	}
	if temperatureRejected(&serviceError{status: 500, msg: "temperature"}) {
		t.Error("non-400 treated as a temperature refusal")
	}
}
