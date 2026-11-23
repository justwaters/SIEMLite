package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"siemlite/pkg/secret"
)

// memStore is a settings store in memory.
type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Setting(_ context.Context, k, def string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[k]; ok {
		return v, nil
	}
	return def, nil
}

func (s *memStore) SetSetting(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

// fakeOllama serves the parts of Ollama SIEMLite uses.
type fakeOllama struct {
	mu      sync.Mutex
	models  []string
	pulls   int
	answer  string
	lastReq map[string]any
}

func (f *fakeOllama) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tags", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var ms []map[string]any
		for _, m := range f.models {
			ms = append(ms, map[string]any{"name": m, "size": 123})
		}
		json.NewEncoder(w).Encode(map[string]any{"models": ms})
	})
	mux.HandleFunc("GET /api/ps", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"models": []map[string]any{{"size_vram": 0}}})
	})
	mux.HandleFunc("POST /api/pull", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Model string }
		json.NewDecoder(r.Body).Decode(&req)
		for _, st := range []string{`{"status":"pulling manifest"}`, `{"status":"pulling abc","total":100,"completed":50}`, `{"status":"success"}`} {
			fmt.Fprintln(w, st)
		}
		f.mu.Lock()
		f.pulls++
		f.models = append(f.models, req.Model)
		f.mu.Unlock()
	})
	mux.HandleFunc("POST /api/chat", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.lastReq = req
		a := f.answer
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"message": map[string]any{"content": a}})
	})
	return mux
}

func newTestService(t *testing.T, def Defaults) (*Service, *memStore) {
	t.Helper()
	st := &memStore{}
	return NewService(st, secret.NewBox(filepath.Join(t.TempDir(), "k.key")), def, nil), st
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

const sshAnswer = `{"pattern":"Failed password for {user} from {src_ip} port {src_port} ssh2","fields":{},"category":3,"severity":{"from":"fixed","fixed":3}}`

var sshLines = []string{
	"Failed password for root from 203.0.113.7 port 51234 ssh2",
	"Failed password for admin from 198.51.100.23 port 40022 ssh2",
}

func TestLocalModelDownloadsAndSuggests(t *testing.T) {
	fo := &fakeOllama{answer: sshAnswer}
	srv := httptest.NewServer(fo.handler())
	defer srv.Close()
	s, _ := newTestService(t, Defaults{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if st := s.Status(); st.Enabled {
		t.Fatalf("on before set up: %+v", st)
	}
	if _, err := s.Suggest(ctx, sshLines); err != ErrOff {
		t.Fatalf("suggest while off = %v", err)
	}
	if err := s.SetEnabled(ctx, true); err == nil {
		t.Error("turned on before set up")
	}
	for _, bad := range []Settings{
		{Provider: "nope"},
		{Provider: ProviderLocal, OllamaURL: "ftp://x", LocalModel: "m"},
		{Provider: ProviderLocal, OllamaURL: srv.URL + "/path", LocalModel: "m"},
		{Provider: ProviderLocal, OllamaURL: srv.URL, LocalModel: "bad model; rm"},
		{Provider: ProviderCloud, CloudModel: "~anthropic/claude-haiku-latest"}, // no key
	} {
		if err := s.Save(ctx, bad, "", nil); err == nil {
			t.Errorf("saved %+v", bad)
		} else if _, ok := err.(InputError); !ok {
			t.Errorf("%+v: not an input error: %v", bad, err)
		}
	}

	if err := s.Save(ctx, Settings{Provider: ProviderLocal, OllamaURL: srv.URL + "/", LocalModel: "qwen2.5-coder:1.5b"}, "", nil); err != nil {
		t.Fatal(err)
	}
	go s.Run(ctx)
	waitFor(t, "the download", func() bool { return s.Status().Ready })
	if fo.pulls != 1 {
		t.Errorf("pulls = %d", fo.pulls)
	}
	v, err := s.Get(ctx)
	if err != nil || !v.Ready || !v.Enabled || v.Ollama == nil || !v.Ollama.Reachable || v.Pull == nil || v.Pull.Running || v.OllamaURL != srv.URL {
		t.Fatalf("view = %+v %v", v, err)
	}
	sug, err := s.Suggest(ctx, sshLines)
	if err != nil || sug.Matched != 2 {
		t.Fatalf("suggest = %+v %v", sug, err)
	}
	if fo.lastReq["model"] != "qwen2.5-coder:1.5b" || !strings.Contains(fmt.Sprint(fo.lastReq["messages"]), "203.0.113.7") {
		t.Errorf("Ollama got %v", fo.lastReq)
	}
	info, _ := s.Info(ctx)
	if !info.Enabled || !strings.Contains(info.Summary, "qwen2.5-coder:1.5b") {
		t.Errorf("info = %+v", info)
	}
	// Off: no suggestions, and the setting survives.
	if err := s.SetEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Suggest(ctx, sshLines); err != ErrOff {
		t.Errorf("suggest when off = %v", err)
	}
	if st := s.Status(); st.Enabled {
		t.Errorf("status when off = %+v", st)
	}
}

func TestFlagsAreTheStartingSettings(t *testing.T) {
	s, store := newTestService(t, Defaults{OllamaURL: "http://ollama:11434", Model: "qwen2.5-coder:7b"})
	ctx := context.Background()
	v, err := s.Get(ctx)
	if err != nil || !v.Configured || !v.Enabled || v.Provider != ProviderLocal || v.LocalModel != "qwen2.5-coder:7b" {
		t.Fatalf("view = %+v %v", v, err)
	}
	if len(store.m) != 0 {
		t.Error("reading wrote settings")
	}
	// Once the page saves, the saved settings win.
	if err := s.Save(ctx, Settings{Provider: ProviderLocal, OllamaURL: "http://other:11434", LocalModel: "qwen2.5-coder:3b"}, "", nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get(ctx); v.OllamaURL != "http://other:11434" || v.LocalModel != "qwen2.5-coder:3b" {
		t.Errorf("after save = %+v", v)
	}
}

// fakeOpenRouter serves the parts of OpenRouter SIEMLite uses.
type fakeOpenRouter struct {
	mu   sync.Mutex
	key  string
	sent []string // request bodies
	resp func(body string) string
}

func (f *fakeOpenRouter) handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+f.key {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"No auth credentials found"}}`)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /models", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":[
			{"id":"~anthropic/claude-haiku-latest","name":"Claude Haiku","supported_parameters":["structured_outputs"],"pricing":{"prompt":"0.000001","completion":"0.000005"},"architecture":{"output_modalities":["text"]}},
			{"id":"x/free-one:free","name":"Free one","supported_parameters":["structured_outputs"],"pricing":{"prompt":"0","completion":"0"}},
			{"id":"x/no-json","name":"No JSON","supported_parameters":["temperature"],"pricing":{"prompt":"0.000001","completion":"0.000001"}},
			{"id":"x/img","name":"Images","supported_parameters":["structured_outputs"],"pricing":{"prompt":"0.000001","completion":"0.000001"},"architecture":{"output_modalities":["image"]}},
			{"id":"x/batch:batch","name":"Batch","supported_parameters":["structured_outputs"],"pricing":{"prompt":"0.000001","completion":"0.000001"}}]}`)
	})
	mux.HandleFunc("GET /key", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			io.WriteString(w, `{"data":{"label":"sk-or-v1-abc...xyz","limit_remaining":4.5}}`)
		}
	})
	mux.HandleFunc("POST /chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.sent = append(f.sent, string(b))
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]any{"content": f.resp(string(b))}}}})
	})
	return mux
}

func TestCloudModelWithMaskedAddresses(t *testing.T) {
	fr := &fakeOpenRouter{key: "sk-or-test"}
	// The model answers with a pattern that keeps one address as literal text.
	fr.resp = func(body string) string {
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		json.Unmarshal([]byte(body), &req)
		var fake string
		for _, m := range req.Messages {
			if g := regexp.MustCompile(`Blocked \S+ to (\S+) mail`).FindStringSubmatch(m.Content); g != nil && fake == "" {
				fake = g[1]
			}
		}
		return "```json\n" + `{"pattern":"Blocked {src_ip} to ` + fake + ` mail {user}","fields":{},"category":4,"severity":{"from":"auto"}}` + "\n```"
	}
	srv := httptest.NewServer(fr.handler())
	defer srv.Close()
	s, store := newTestService(t, Defaults{})
	s.OpenRouterURL = srv.URL
	ctx := context.Background()
	key := "sk-or-test"
	if err := s.Save(ctx, Settings{Provider: ProviderCloud, CloudModel: "~anthropic/claude-haiku-latest"}, "", &key); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(store.m[settingKey], key) {
		t.Fatal("the key was stored in the clear")
	}
	v, _ := s.Get(ctx)
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), key) || !v.HasKey || !v.Ready || v.Ollama != nil {
		t.Fatalf("view = %s", raw)
	}
	lines := []string{
		"Blocked 203.0.113.7 to 10.20.30.40 mail bob@corp.example.org",
		"Blocked 198.51.100.23 to 10.20.30.40 mail alice@corp.example.org",
	}
	sug, err := s.Suggest(ctx, lines)
	if err != nil {
		t.Fatal(err)
	}
	if sug.Matched != 2 || !strings.Contains(sug.Definition.Pattern, "10.20.30.40") {
		t.Errorf("suggestion = %+v", sug)
	}
	for _, body := range fr.sent {
		for _, real := range []string{"203.0.113.7", "198.51.100.23", "10.20.30.40", "bob@corp.example.org", "alice@corp.example.org"} {
			if strings.Contains(body, real) {
				t.Errorf("%s was sent to the cloud", real)
			}
		}
		if !strings.Contains(body, `"data_collection":"deny"`) || !strings.Contains(body, `"require_parameters":true`) {
			t.Errorf("provider preferences missing: %s", body)
		}
	}

	// Without masking, lines go as they are.
	if err := s.Save(ctx, Settings{Provider: ProviderCloud, CloudModel: "~anthropic/claude-haiku-latest", SendAddresses: true}, "", nil); err != nil {
		t.Fatal(err)
	}
	fr.sent = nil
	s.Suggest(ctx, lines)
	if len(fr.sent) == 0 || !strings.Contains(fr.sent[0], "203.0.113.7") {
		t.Error("unmasked lines weren't sent as they are")
	}

	// Allowing free models is kept, and off unless asked for.
	if v, err := s.Get(ctx); err != nil || v.AllowFree {
		t.Errorf("free models allowed by default: %v %v", v.AllowFree, err)
	}
	if err := s.Save(ctx, Settings{Provider: ProviderCloud, CloudModel: "~anthropic/claude-haiku-latest", SendAddresses: true, AllowFree: true}, "", nil); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Get(ctx); err != nil || !v.AllowFree {
		t.Errorf("allow free models wasn't kept: %v %v", v.AllowFree, err)
	}

	// Test checks the key; a wrong key is explained.
	if r, err := s.Test(ctx, Settings{Provider: ProviderCloud, CloudModel: "~anthropic/claude-haiku-latest"}, nil); err != nil || r.KeyLabel == "" || r.CreditLeft == nil || r.ModelKnown == nil || !*r.ModelKnown {
		t.Errorf("test = %+v %v", r, err)
	}
	bad := "sk-or-wrong"
	if _, err := s.Test(ctx, Settings{Provider: ProviderCloud, CloudModel: "x"}, &bad); err == nil || !strings.Contains(err.Error(), "refused the API key") {
		t.Errorf("wrong key = %v", err)
	}
	// The model list keeps models that can answer in JSON, as text, not batch.
	models, _, err := s.CloudModels(ctx, ProviderCloud, nil)
	if err != nil || len(models) != 2 || models[0].Prompt != "1" || models[0].Output != "5" || !models[1].Free {
		t.Errorf("models = %+v %v", models, err)
	}
	// Removing the key takes the cloud out of use.
	empty := ""
	if err := s.Save(ctx, Settings{Provider: ProviderCloud, CloudModel: "~anthropic/claude-haiku-latest"}, "", &empty); err == nil {
		t.Error("cloud saved with the key removed")
	}
}

func TestMasker(t *testing.T) {
	m := newMasker(nil)
	m.seen.WriteString("real text with 192.0.2.1 already in it\n")
	in := "from 10.0.0.1 to 10.0.0.10 and 10.0.0.1 again, 2001:db8:1::5, mail a.b@x.io, time 10:17:12, mac aa:bb:cc:dd:ee:ff"
	out := m.mask(in)
	for _, real := range []string{"10.0.0.1 ", "10.0.0.10", "2001:db8:1::5", "a.b@x.io"} {
		if strings.Contains(out, real) {
			t.Errorf("%q kept in %q", real, out)
		}
	}
	if strings.Contains(out, "192.0.2.1 ") || strings.Contains(out, "192.0.2.1,") {
		t.Errorf("a stand-in equals an address already in the text: %q", out)
	}
	if !strings.Contains(out, "10:17:12") || strings.Contains(out, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("a time was changed, or a MAC address kept: %q", out)
	}
	if back := m.unmask(out); back != in {
		t.Errorf("unmask = %q", back)
	}
	// Only whole addresses are put back.
	f := m.toFake["10.0.0.1"]
	if got := m.unmask("x " + f + "5 y"); strings.Contains(got, "10.0.0.1") {
		t.Errorf("a longer address was changed: %q", got)
	}
}

func TestRecommend(t *testing.T) {
	for _, c := range []struct {
		hw   Hardware
		want string
	}{
		{Hardware{CPUs: 2, Memory: 4 * gb}, "qwen2.5-coder:1.5b"},
		{Hardware{CPUs: 4, Memory: 8 * gb}, "qwen2.5-coder:3b"},
		{Hardware{CPUs: 4, Memory: 64 * gb}, "qwen2.5-coder:3b"}, // memory, but too few cores for 7b
		{Hardware{CPUs: 8, Memory: 16 * gb}, "qwen2.5-coder:7b"},
		{Hardware{CPUs: 32, Memory: 64 * gb}, "qwen2.5-coder:7b"}, // 14b needs a GPU
		{Hardware{CPUs: 8, Memory: 32 * gb, GPU: true}, "qwen2.5-coder:14b"},
		{Hardware{CPUs: 16, Memory: 6 * gb, GPU: true}, "qwen2.5-coder:1.5b"},
	} {
		if got := Recommend(c.hw); got != c.want {
			t.Errorf("Recommend(%+v) = %s, want %s", c.hw, got, c.want)
		}
	}
	if hw := DetectHardware(); hw.CPUs < 1 {
		t.Errorf("hardware = %+v", hw)
	}
}
