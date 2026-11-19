package chatnotify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Setting(_ context.Context, k, d string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[k]; ok {
		return v, nil
	}
	return d, nil
}
func (s *memStore) SetSetting(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

type hook struct {
	srv  *httptest.Server
	mu   sync.Mutex
	got  []map[string]any
	code int
}

func newHook(t *testing.T) *hook {
	h := &hook{code: 200}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		h.mu.Lock()
		h.got = append(h.got, v)
		code := h.code
		h.mu.Unlock()
		if code != 200 {
			http.Error(w, "no_service", code)
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(h.srv.Close)
	return h
}
func (h *hook) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.got) }

func newSvc(t *testing.T, kind Kind) (*Service, *memStore) {
	st := &memStore{m: map[string]string{}}
	s := New(kind, st, filepath.Join(t.TempDir(), "key"))
	s.AnyHost = true
	return s, st
}

func TestWebhookAddressChecks(t *testing.T) {
	sl, _ := newSvc(t, Slack)
	sl.AnyHost = false
	te, _ := newSvc(t, Teams)
	te.AnyHost = false
	for _, tc := range []struct {
		s    *Service
		url  string
		good bool
	}{
		{sl, "https://hooks.slack.com/services/T0/B0/xyz", true},
		{sl, "http://hooks.slack.com/services/T0/B0/xyz", false},
		{sl, "https://evil.example/services/T0/B0/xyz", false},
		{sl, "https://hooks.slack.com.evil.example/x", false},
		{sl, "not a url", false},
		{te, "https://prod-12.westus.logic.azure.com:443/workflows/abc", true},
		{te, "https://contoso.webhook.office.com/webhookb2/abc", true},
		{te, "https://hooks.slack.com/services/T0/B0/xyz", false},
		{te, "https://169.254.169.254/latest", false},
	} {
		if got := tc.s.CheckWebhook(tc.url) == ""; got != tc.good {
			t.Errorf("%s %q: accepted=%v, want %v", tc.s.ID(), tc.url, got, tc.good)
		}
	}
}

func TestSaveKeepsTheWebhookSecret(t *testing.T) {
	ctx := context.Background()
	s, st := newSvc(t, Slack)
	h := newHook(t)
	if err := s.Save(ctx, nil, 4); err == nil {
		t.Error("saved with no address")
	}
	if err := s.Save(ctx, ptr(h.srv.URL+"/services/SECRETKEY"), 9); err == nil {
		t.Error("an odd severity was accepted")
	}
	if err := s.Save(ctx, ptr(h.srv.URL+"/services/SECRETKEY"), 3); err != nil {
		t.Fatal(err)
	}
	if raw, _ := st.Setting(ctx, "chat_slack", ""); strings.Contains(raw, "SECRETKEY") {
		t.Errorf("the address is saved in the clear: %s", raw)
	}
	v, _ := s.Get(ctx)
	if b, _ := json.Marshal(v); strings.Contains(string(b), "SECRETKEY") || !v.Configured || !v.Enabled || v.MinSeverity != 3 {
		t.Errorf("view = %s", b)
	}
	// Changing only the severity keeps the address.
	if err := s.Save(ctx, nil, 5); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get(ctx); !v.Configured || v.MinSeverity != 5 {
		t.Errorf("after changing the severity: %+v", v)
	}
	if err := s.SetEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get(ctx); v.Enabled || !v.Configured {
		t.Errorf("after turning off: %+v", v)
	}
	// Removing the address clears it.
	if err := s.Save(ctx, ptr(""), 4); err == nil {
		// an empty address clears the integration
		if v, _ := s.Get(ctx); v.Configured {
			t.Errorf("still configured after removing the address: %+v", v)
		}
	}
}

func ptr(s string) *string { return &s }

func TestNotifyPostsOnlySeriousAlertsInThePlatformsFormat(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []Kind{Slack, Teams} {
		s, _ := newSvc(t, kind)
		h := newHook(t)
		if err := s.Save(ctx, ptr(h.srv.URL+"/x"), 4); err != nil {
			t.Fatal(err)
		}
		s.Notify(ctx, Alert{Title: "Low one", Severity: 2})
		if h.count() != 0 {
			t.Fatalf("%s: a Low alert was posted with the minimum at High", kind)
		}
		s.Notify(ctx, Alert{Title: "SSH brute force", Severity: 4, GroupBy: "src_ip", GroupValue: "203.0.113.7", Count: 12, Description: "Many failed logins."})
		if h.count() != 1 {
			t.Fatalf("%s: %d posts, want 1", kind, h.count())
		}
		b, _ := json.Marshal(h.got[0])
		text := string(b)
		for _, want := range []string{"SSH brute force", "203.0.113.7", "12", "High"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: message lacks %q: %s", kind, want, text)
			}
		}
		if kind == Teams && !strings.Contains(text, "application/vnd.microsoft.card.adaptive") {
			t.Errorf("Teams message isn't an adaptive card: %s", text)
		}
		if kind == Slack && !strings.Contains(text, `"blocks"`) {
			t.Errorf("Slack message has no blocks: %s", text)
		}
		if v, _ := s.Get(ctx); v.LastSent == 0 || v.LastError != "" {
			t.Errorf("%s: last sent not recorded: %+v", kind, v)
		}
		// Off means nothing is posted.
		_ = s.SetEnabled(ctx, false)
		s.Notify(ctx, Alert{Title: "x", Severity: 5})
		if h.count() != 1 {
			t.Errorf("%s: posted while turned off", kind)
		}
	}
}

func TestFailuresAreKeptWithoutTheAddress(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t, Slack)
	h := newHook(t)
	h.code = 404
	if err := s.Save(ctx, ptr(h.srv.URL+"/services/SECRETKEY"), 4); err != nil {
		t.Fatal(err)
	}
	s.Notify(ctx, Alert{Title: "x", Severity: 5})
	v, _ := s.Get(ctx)
	if !strings.Contains(v.LastError, "refused") || strings.Contains(v.LastError, "SECRETKEY") {
		t.Errorf("last error = %q", v.LastError)
	}
	if info, _ := s.Info(ctx); info.State != "error" {
		t.Errorf("the card doesn't show the failure: %+v", info)
	}
	// A transport failure doesn't leak the address either.
	h.srv.Close()
	s.Notify(ctx, Alert{Title: "x", Severity: 5})
	if v, _ := s.Get(ctx); strings.Contains(v.LastError, "SECRETKEY") || v.LastError == "" {
		t.Errorf("last error = %q", v.LastError)
	}
	if err := s.Test(ctx, "", "root"); err == nil || strings.Contains(err.Error(), "SECRETKEY") {
		t.Errorf("test error = %v", err)
	}
}

func TestAtMostTenAMinuteAndTheRestAreCounted(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t, Slack)
	h := newHook(t)
	if err := s.Save(ctx, ptr(h.srv.URL+"/x"), 2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 14; i++ {
		s.Notify(ctx, Alert{Title: "a", Severity: 4})
	}
	if h.count() != perMinute {
		t.Fatalf("%d posts in a minute, want %d", h.count(), perMinute)
	}
	s.rateMu.Lock()
	s.winFrom = time.Now().Add(-2 * time.Minute)
	s.rateMu.Unlock()
	s.Notify(ctx, Alert{Title: "later", Severity: 4})
	last, _ := json.Marshal(h.got[h.count()-1])
	if !strings.Contains(string(last), "4 more alerts opened") {
		t.Errorf("the held-back alerts weren't mentioned: %s", last)
	}
}
