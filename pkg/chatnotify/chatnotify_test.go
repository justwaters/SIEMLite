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
		{te, "https://management.azure.com/x", false},
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
	s.rate[0].from = time.Now().Add(-2 * time.Minute)
	s.rateMu.Unlock()
	s.Notify(ctx, Alert{Title: "later", Severity: 4})
	last, _ := json.Marshal(h.got[h.count()-1])
	if !strings.Contains(string(last), "4 more alerts opened") {
		t.Errorf("the held-back alerts weren't mentioned: %s", last)
	}
}

// Hand-raised alerts have their own small budget, so they can't crowd out detected ones; and what
// an attacker can put in a log can't make a link or a channel ping in Slack.
func TestManualAlertsHaveTheirOwnBudgetAndTextIsEscaped(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t, Slack)
	h := newHook(t)
	if err := s.Save(ctx, ptr(h.srv.URL+"/x"), 2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		s.Notify(ctx, Alert{Title: "by hand", Severity: 5, Manual: true})
	}
	if h.count() != manualPerMinute {
		t.Fatalf("%d hand-raised posts, want %d", h.count(), manualPerMinute)
	}
	s.Notify(ctx, Alert{Title: "detected", Severity: 4, GroupBy: "user", GroupValue: "<!channel> <https://evil.example|click>", Description: "a <!here> b & c"})
	if h.count() != manualPerMinute+1 {
		t.Fatal("a detected alert was held back by hand-raised ones")
	}
	b, _ := json.Marshal(h.got[h.count()-1])
	for _, bad := range []string{`<!channel>`, `<https://evil.example`, `<!here>`} {
		if strings.Contains(strings.ReplaceAll(string(b), `\u003c`, "<"), bad) {
			t.Errorf("unescaped %q in %s", bad, b)
		}
	}
}

func TestRedirectsAreNotFollowedAndBodiesNotEchoed(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t, Slack)
	target := newHook(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	err := s.Test(ctx, redirect.URL+"/x", "root")
	if err == nil || target.count() != 0 {
		t.Errorf("a redirect was followed: err=%v, %d requests at the target", err, target.count())
	}
	body := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "INTERNAL-DETAIL-xyz", 500)
	}))
	defer body.Close()
	if err := s.Test(ctx, body.URL+"/x", "root"); err == nil || strings.Contains(err.Error(), "INTERNAL-DETAIL") {
		t.Errorf("the far end's words were echoed: %v", err)
	}
}

// A webhook address with credentials in it is refused, even on an allowed host.
func TestCheckWebhookRefusesUserInfo(t *testing.T) {
	svc := New(Slack, nil, "")
	for _, raw := range []string{"https://user:pw@hooks.slack.com/services/T/B/x", "https://user@hooks.slack.com/services/T/B/x"} {
		if svc.CheckWebhook(raw) == "" {
			t.Errorf("%q was accepted", raw)
		}
	}
	if svc.CheckWebhook("https://hooks.slack.com/services/T/B/x") != "" {
		t.Error("a plain Slack address was refused")
	}
}

func TestSlackNotificationTextCannotPingAChannel(t *testing.T) {
	s, _ := newSvc(t, Slack)
	var v struct {
		Text        string `json:"text"`
		Attachments []struct {
			Blocks []struct {
				Text struct{ Type, Text string } `json:"text"`
			} `json:"blocks"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(s.payload(Alert{Title: "<!channel> & <@U1|x>", Severity: 5}), &v); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(v.Text, "<>") || !strings.Contains(v.Text, "&lt;!channel&gt; &amp; &lt;@U1|x&gt;") {
		t.Errorf("notification text %q", v.Text)
	}
	if h := v.Attachments[0].Blocks[0].Text; h.Type != "plain_text" || !strings.Contains(h.Text, "<!channel>") {
		t.Errorf("the plain-text header should show the name as it is: %+v", h)
	}
}

func TestTeamsHostNeedsALabelBeforeTheSuffix(t *testing.T) {
	s, _ := newSvc(t, Teams)
	s.AnyHost = false
	for _, u := range []string{"https://.logic.azure.com/x", "https://a..logic.azure.com/x", "https://.webhook.office.com/"} {
		if s.CheckWebhook(u) == "" {
			t.Errorf("%q was accepted", u)
		}
	}
	if s.CheckWebhook("https://prod-12.westus.logic.azure.com:443/workflows/x") != "" {
		t.Error("a real workflow address was refused")
	}
}

func TestWebhookHostCharactersAreLimited(t *testing.T) {
	s, _ := newSvc(t, Teams)
	s.AnyHost = false
	if s.CheckWebhook("https://0!.logic.azure.com/x") == "" || s.CheckWebhook("https://a_b.logic.azure.com/x") == "" {
		t.Error("a host with odd characters was accepted")
	}
}

// A long title or description is cut to what Slack accepts rather than losing the alert.
func TestSlackMessageStaysWithinSlackLimits(t *testing.T) {
	long := strings.Repeat("é", 5000)
	b, _ := json.Marshal(slackMessage(Alert{Severity: 4, Title: long, Description: long, Note: long}))
	var m struct {
		Attachments []struct {
			Blocks []struct {
				Text struct{ Text string }
			}
		}
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	bl := m.Attachments[0].Blocks
	if n := len([]rune(bl[0].Text.Text)); n > 150 {
		t.Errorf("header has %d characters", n)
	}
	if n := len([]rune(bl[1].Text.Text)); n > 3000 {
		t.Errorf("section has %d characters", n)
	}
}
