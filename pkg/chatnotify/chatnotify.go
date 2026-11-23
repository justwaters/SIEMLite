// Package chatnotify posts a message to Slack or Microsoft Teams when SIEMLite opens an alert.
// Each is its own integration with its own settings; both use an incoming-webhook address, which
// is kept sealed like a password because anyone who has it can post to the channel.
package chatnotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"siemlite/pkg/integrations"
	"siemlite/pkg/secret"
)

// Kind is the service a Service posts to.
type Kind string

const (
	Slack Kind = "slack"
	Teams Kind = "teams"
)

// Choices for the lowest severity that is posted (OCSF severity ids).
var MinSeverities = []int{2, 3, 4, 5}

const (
	defaultMin      = 4 // High
	perMinute       = 10
	manualPerMinute = 3
	sendTimeout     = 10 * time.Second
	maxBody         = 1 << 20
	maxNameBytes    = 200
)

// Store is where settings are kept (storage.Repository).
type Store interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Alert is what a message says.
type Alert struct {
	Title       string // the rule's name
	Description string
	Severity    int // 1 informational … 6 fatal
	GroupBy     string
	GroupValue  string
	Count       int64
	Note        string
	At          time.Time
	// Manual is an alert a person or an AI agent raised by hand. It has a small budget of its own, so a
	// stream of them can't use up the messages meant for the alerts SIEMLite detects.
	Manual bool
}

// SeverityName is the word for an OCSF severity.
func SeverityName(n int) string {
	return map[int]string{1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal"}[n]
}

// Service is one integration: Slack or Teams.
type Service struct {
	kind  Kind
	store Store
	box   *secret.Box
	// Client posts the messages; AnyHost turns off the check that the address is the service's own
	// (for tests).
	Client  *http.Client
	AnyHost bool

	mu     sync.Mutex // one change to the saved settings at a time
	rateMu sync.Mutex
	rate   [2]window // detected alerts, hand-raised alerts
}

type window struct {
	from    time.Time
	sent    int
	dropped int
}

// New returns the Slack or Teams integration, keeping its webhook's key at keyPath.
func New(kind Kind, store Store, keyPath string) *Service {
	// Redirects are not followed: the address was checked, wherever it might send us was not.
	client := &http.Client{Timeout: sendTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Service{kind: kind, store: store, box: secret.NewBox(keyPath), Client: client}
}

func (s *Service) key() string { return "chat_" + string(s.kind) }

// ID, Name and Description are shown on the integration's card.
func (s *Service) ID() string { return string(s.kind) }
func (s *Service) Name() string {
	if s.kind == Teams {
		return "Microsoft Teams"
	}
	return "Slack"
}
func (s *Service) Description() string {
	return "Post a message to a " + map[Kind]string{Slack: "Slack", Teams: "Microsoft Teams"}[s.kind] + " channel whenever SIEMLite opens an alert."
}

type stored struct {
	Webhook     string `json:"webhook,omitempty"` // sealed
	MinSeverity int    `json:"min_severity,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	LastSent    int64  `json:"last_sent,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

// View is what the settings show. The webhook address is never included.
type View struct {
	Configured     bool   `json:"configured"`
	Enabled        bool   `json:"enabled"`
	MinSeverity    int    `json:"min_severity"`
	MinSeverities  []int  `json:"min_severities"`
	Unreadable     bool   `json:"unreadable,omitempty"` // saved, but this server's key can't open it
	LastSent       int64  `json:"last_sent,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	WebhookExample string `json:"webhook_example"`
}

func (s *Service) load(ctx context.Context) (stored, error) {
	raw, err := s.store.Setting(ctx, s.key(), "")
	if err != nil || raw == "" {
		return stored{}, err
	}
	var st stored
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return stored{}, fmt.Errorf("saved %s settings are damaged: %w", s.Name(), err)
	}
	return st, nil
}

func (s *Service) save(ctx context.Context, st stored) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.store.SetSetting(ctx, s.key(), string(b))
}

func (st stored) min() int {
	if st.MinSeverity == 0 {
		return defaultMin
	}
	return st.MinSeverity
}

// Get returns the saved settings.
func (s *Service) Get(ctx context.Context) (View, error) {
	st, err := s.load(ctx)
	if err != nil {
		return View{}, err
	}
	v := View{Configured: st.Webhook != "", MinSeverity: st.min(), MinSeverities: MinSeverities, LastSent: st.LastSent, LastError: st.LastError}
	v.Enabled = v.Configured && !st.Disabled
	if st.Webhook != "" {
		if _, err := s.box.Open(st.Webhook); err != nil {
			v.Unreadable = true
		}
	}
	if s.kind == Teams {
		v.WebhookExample = "https://prod-00.westus.logic.azure.com/workflows/…"
	} else {
		v.WebhookExample = "https://hooks.slack.com/services/T000/B000/…"
	}
	return v, nil
}

// Info reports the card's state.
func (s *Service) Info(ctx context.Context) (integrations.Info, error) {
	v, err := s.Get(ctx)
	if err != nil {
		return integrations.Info{}, err
	}
	info := integrations.Info{Configured: v.Configured, Enabled: v.Enabled}
	if v.Configured {
		info.Summary = fmt.Sprintf("Posts alerts of %s and above.", SeverityName(v.MinSeverity))
		if v.Unreadable {
			info.Summary += " The saved address can't be read on this server; enter it again."
		} else if v.LastError != "" {
			info.State, info.Summary = integrations.StateError, "The last message failed: "+v.LastError
		}
	}
	return info, nil
}

// SetEnabled turns posting on or off without touching the settings.
func (s *Service) SetEnabled(ctx context.Context, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	if st.Webhook == "" {
		return integrations.InputError("Save the webhook address first.")
	}
	st.Disabled = !on
	return s.save(ctx, st)
}

// CheckWebhook says what is wrong with a webhook address, or "".
func (s *Service) CheckWebhook(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "That isn't a web address. Paste the webhook URL."
	}
	if s.AnyHost {
		return ""
	}
	if u.Scheme != "https" {
		return "The webhook address must start with https://."
	}
	if u.User != nil {
		return "The webhook address must not contain a user name or password."
	}
	host := strings.ToLower(u.Hostname())
	ok := false
	switch s.kind {
	case Slack:
		ok = host == "hooks.slack.com" || host == "hooks.slack-gov.com"
	case Teams:
		for _, suffix := range []string{".logic.azure.com", ".webhook.office.com", ".powerplatform.com", ".api.powerplatform.com"} {
			ok = ok || strings.HasSuffix(host, suffix) && !strings.HasPrefix(host, ".") && !strings.Contains(host, "..")
		}
	}
	if strings.Trim(host, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
		ok = false // letters, digits, dots and hyphens only; anything else in a host name is a trick
	}
	if !ok {
		if s.kind == Teams {
			return "That doesn't look like a Teams workflow address (it should end in .logic.azure.com, .webhook.office.com or .powerplatform.com)."
		}
		return "That doesn't look like a Slack webhook (it should start with https://hooks.slack.com/services/)."
	}
	return ""
}

// Save stores the settings. A nil webhook keeps the saved one.
func (s *Service) Save(ctx context.Context, webhook *string, minSeverity int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := false
	for _, m := range MinSeverities {
		ok = ok || m == minSeverity
	}
	if !ok {
		return integrations.InputError("Choose Low, Medium, High or Critical as the lowest severity to post.")
	}
	st, err := s.load(ctx)
	if err != nil {
		st = stored{} // damaged settings are replaced
	}
	if webhook != nil {
		w := strings.TrimSpace(*webhook)
		if w == "" {
			st = stored{MinSeverity: minSeverity} // removing the address clears the integration
			return s.save(ctx, st)
		}
		if msg := s.CheckWebhook(w); msg != "" {
			return integrations.InputError(msg)
		}
		if st.Webhook, err = s.box.Seal(w); err != nil {
			return err
		}
		st.LastError = ""
	}
	if st.Webhook == "" {
		return integrations.InputError("Paste the webhook address.")
	}
	st.MinSeverity = minSeverity
	return s.save(ctx, st)
}

// Test posts a message to webhook, or to the saved address when it is empty.
func (s *Service) Test(ctx context.Context, webhook string, by string) error {
	hook := strings.TrimSpace(webhook)
	if hook == "" {
		st, err := s.load(ctx)
		if err != nil {
			return err
		}
		if st.Webhook == "" {
			return integrations.InputError("Paste the webhook address first.")
		}
		if hook, err = s.box.Open(st.Webhook); err != nil {
			return integrations.InputError("The saved address can't be read on this server. Paste it again.")
		}
	} else if msg := s.CheckWebhook(hook); msg != "" {
		return integrations.InputError(msg)
	}
	return s.post(ctx, hook, s.payload(Alert{Title: "SIEMLite test message", Severity: 1, At: time.Now(),
		Description: "Sent by " + by + ". If you can read this, alerts will be posted here."}))
}

// Notify posts an alert if the integration is on and the alert is serious enough. It never blocks
// the caller for long and never fails it: a problem is kept for the card to show. At most 10
// messages go out a minute; the ones held back are counted in the next message.
func (s *Service) Notify(ctx context.Context, a Alert) {
	st, err := s.load(ctx)
	if err != nil || st.Webhook == "" || st.Disabled || a.Severity < st.min() {
		return
	}
	hook, err := s.box.Open(st.Webhook)
	if err != nil {
		return
	}
	cls, limit := 0, perMinute
	if a.Manual {
		cls, limit = 1, manualPerMinute
	}
	s.rateMu.Lock()
	now := time.Now()
	w := &s.rate[cls]
	if now.Sub(w.from) >= time.Minute {
		w.from, w.sent = now, 0
	}
	if w.sent >= limit {
		w.dropped++
		s.rateMu.Unlock()
		return
	}
	w.sent++
	held := w.dropped
	w.dropped = 0
	s.rateMu.Unlock()
	if held > 0 {
		a.Note = strings.TrimSpace(a.Note + fmt.Sprintf(" %d more %s opened in the last minute and weren't posted.", held, map[bool]string{true: "alert", false: "alerts"}[held == 1]))
	}
	cctx, cancel := context.WithTimeout(ctx, sendTimeout+5*time.Second)
	defer cancel()
	err = s.post(cctx, hook, s.payload(a))
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, lerr := s.load(ctx)
	if lerr != nil {
		return
	}
	if err != nil {
		cur.LastError = err.Error()
	} else {
		cur.LastError, cur.LastSent = "", time.Now().UnixMilli()
	}
	_ = s.save(ctx, cur)
}

func (s *Service) post(ctx context.Context, hook string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SIEMLite")
	resp, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("couldn't reach %s: %s", s.Name(), trim(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	if resp.StatusCode/100 != 2 {
		// Only the status is reported: what the far end says in the body isn't repeated back.
		return fmt.Errorf("%s refused it (%s)", s.Name(), resp.Status)
	}
	return nil
}

// trim keeps a transport error short and drops the URL, which holds the secret.
func trim(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if len(s) > maxNameBytes {
		s = s[:maxNameBytes]
	}
	return s
}

func (s *Service) payload(a Alert) []byte {
	var v any
	if s.kind == Teams {
		v = teamsCard(a)
	} else {
		v = slackMessage(a)
	}
	b, _ := json.Marshal(v)
	return b
}

var sevColor = map[int]string{1: "#8a94a0", 2: "#2fa36b", 3: "#d9a21a", 4: "#e8742a", 5: "#d93b3b", 6: "#a31515"}

func who(a Alert) string {
	if a.GroupValue == "" {
		return ""
	}
	label := map[string]string{"src_ip": "Source IP", "dst_ip": "Destination IP", "user": "User", "host": "Host", "source": "Source"}[a.GroupBy]
	if label == "" {
		label = "For"
	}
	return label + ": " + a.GroupValue
}

// esc makes text safe inside Slack's mrkdwn: & < > start links, mentions and channel pings.
var esc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace

func slackMessage(a Alert) any {
	head := fmt.Sprintf("%s alert: %s", SeverityName(a.Severity), a.Title)
	var lines []string
	if w := who(a); w != "" {
		lines = append(lines, "*"+strings.Replace(esc(w), ": ", ":* ", 1))
	}
	if a.Count > 0 {
		lines = append(lines, fmt.Sprintf("*Events:* %d", a.Count))
	}
	if a.Description != "" {
		lines = append(lines, esc(a.Description))
	}
	if a.Note != "" {
		lines = append(lines, "_"+esc(a.Note)+"_")
	}
	// Slack refuses a header over 150 characters and a section over 3000, which would lose the alert.
	blocks := []any{map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": clip(head, 150)}}}
	if len(lines) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": clip(strings.Join(lines, "\n"), 3000)}})
	}
	// "text" is read as markup too (it is the notification text), so it is escaped; the header block is plain text.
	return map[string]any{"text": clip(esc(head), 3000), "attachments": []any{map[string]any{"color": sevColor[a.Severity], "blocks": blocks}}}
}

// teamsCard is an Adaptive Card in a message, which is what a Teams workflow's "when a webhook
// request is received" trigger accepts.
func teamsCard(a Alert) any {
	head := fmt.Sprintf("%s alert: %s", SeverityName(a.Severity), a.Title)
	color := "Accent"
	switch {
	case a.Severity >= 5:
		color = "Attention"
	case a.Severity == 4:
		color = "Warning"
	case a.Severity == 2 || a.Severity == 3:
		color = "Good"
	}
	body := []any{map[string]any{"type": "TextBlock", "text": head, "weight": "Bolder", "size": "Medium", "wrap": true, "color": color}}
	var facts []any
	if w := who(a); w != "" {
		k, v, _ := strings.Cut(w, ": ")
		facts = append(facts, map[string]any{"title": k, "value": v})
	}
	if a.Count > 0 {
		facts = append(facts, map[string]any{"title": "Events", "value": fmt.Sprint(a.Count)})
	}
	if len(facts) > 0 {
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	}
	for _, t := range []string{a.Description, a.Note} {
		if t != "" {
			body = append(body, map[string]any{"type": "TextBlock", "text": t, "wrap": true, "isSubtle": true})
		}
	}
	return map[string]any{"type": "message", "attachments": []any{map[string]any{
		"contentType": "application/vnd.microsoft.card.adaptive",
		"content":     map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body},
	}}}
}

// clip cuts s to at most n characters (not bytes), ending in an ellipsis when it was cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := string(r[:n-1])
	// Don't end in half of an escaped &amp; &lt; or &gt;.
	if i := strings.LastIndex(cut, "&"); i >= 0 && len(cut)-i <= 5 && !strings.Contains(cut[i:], ";") {
		cut = cut[:i]
	}
	return cut + "…"
}
