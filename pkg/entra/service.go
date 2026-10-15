package entra

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"siemlite/pkg/integrations"
	"siemlite/pkg/secret"
	"siemlite/pkg/storage"
)

const (
	settingKey     = "entra"
	syncSettingKey = "entra_sync"
	// SyncEvery is how often group membership is checked in the background.
	SyncEvery = 5 * time.Minute
	flowTTL   = 10 * time.Minute
)

// Store is where settings are kept (storage.Repository).
type Store interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Login error codes. They are shown to the person by code, not by text, so
// nothing from Microsoft is repeated back to the browser.
const (
	CodeNotInGroup = "not_in_group"
	CodeNameTaken  = "name_taken"
	CodeExpired    = "expired"
	CodeDenied     = "denied"
	CodeFailed     = "failed"
)

// LoginError is a sign-in that didn't succeed. Detail is for the log.
type LoginError struct{ Code, Detail string }

func (e *LoginError) Error() string { return e.Code + ": " + e.Detail }

func failed(detail string, args ...any) *LoginError {
	return &LoginError{Code: CodeFailed, Detail: fmt.Sprintf(detail, args...)}
}

type cachedToken struct {
	token string
	exp   time.Time
}

// Service is the Entra integration.
type Service struct {
	// Authority and Graph are Microsoft's endpoints; empty means the public
	// cloud. They exist so tests can stand in for Microsoft.
	Authority string
	Graph     string

	store Store
	repo  *storage.Repository
	box   *secret.Box
	http  *http.Client
	log   *slog.Logger

	mu       sync.Mutex // one save, test or sync at a time
	keyMu    sync.Mutex
	keySets  map[string]*keySet
	tokMu    sync.Mutex
	tokens   map[string]cachedToken
	lastSync *SyncStatus
}

// NewService returns the integration, keeping its client secret sealed with box.
func NewService(store Store, repo *storage.Repository, box *secret.Box, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: store, repo: repo, box: box, log: log,
		http: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (s *Service) authority() string {
	if s.Authority != "" {
		return strings.TrimRight(s.Authority, "/")
	}
	return DefaultAuthority
}

func (s *Service) graphURL() string {
	if s.Graph != "" {
		return strings.TrimRight(s.Graph, "/")
	}
	return DefaultGraph
}

func (s *Service) keys(tenant string) *keySet {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.keySets == nil {
		s.keySets = map[string]*keySet{}
	}
	if s.keySets[tenant] == nil {
		s.keySets[tenant] = &keySet{}
	}
	return s.keySets[tenant]
}

// --- Settings ---

type stored struct {
	Config
	Secret   string `json:"secret,omitempty"` // sealed
	Disabled bool   `json:"disabled,omitempty"`
}

// SyncStatus is the result of the last membership check.
type SyncStatus struct {
	At       int64  `json:"at"` // unix milliseconds
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Members  int    `json:"members"`  // people in the access group
	Accounts int    `json:"accounts"` // SIEMLite accounts that sign in with Microsoft
	Disabled int    `json:"disabled"` // switched off this time
	Enabled  int    `json:"enabled"`  // switched back on this time
	Changed  int    `json:"changed"`  // roles changed this time
	// Protected counts people who are no longer in the group but were kept,
	// because switching them off would leave no enabled admin.
	Protected int `json:"protected"`
}

// View is what the Integrations page shows. The client secret is never included.
type View struct {
	Config
	Configured       bool        `json:"configured"`
	Enabled          bool        `json:"enabled"`
	HasSecret        bool        `json:"has_secret"`
	SecretUnreadable bool        `json:"secret_unreadable,omitempty"`
	RedirectURI      string      `json:"redirect_uri"`
	LastSync         *SyncStatus `json:"last_sync,omitempty"`
}

func (s *Service) load(ctx context.Context) (stored, error) {
	raw, err := s.store.Setting(ctx, settingKey, "")
	if err != nil || raw == "" {
		return stored{}, err
	}
	var st stored
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return stored{}, fmt.Errorf("saved Entra settings are damaged: %w", err)
	}
	return st, nil
}

func (s *Service) save(ctx context.Context, st stored) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.store.SetSetting(ctx, settingKey, string(b))
}

func (s *Service) status(ctx context.Context) *SyncStatus {
	s.mu.Lock()
	cached := s.lastSync
	s.mu.Unlock()
	if cached != nil {
		return cached
	}
	raw, _ := s.store.Setting(ctx, syncSettingKey, "")
	if raw == "" {
		return nil
	}
	var st SyncStatus
	if json.Unmarshal([]byte(raw), &st) != nil {
		return nil
	}
	return &st
}

// Get returns the saved settings.
func (s *Service) Get(ctx context.Context) (View, error) {
	st, err := s.load(ctx)
	if err != nil {
		return View{}, err
	}
	v := View{Config: st.Config, HasSecret: st.Secret != "", RedirectURI: st.Config.RedirectURI(), LastSync: s.status(ctx)}
	v.Configured = st.TenantID != "" && st.Secret != ""
	v.Enabled = v.Configured && !st.Disabled
	if st.Secret != "" {
		if _, err := s.box.Open(st.Secret); err != nil {
			v.SecretUnreadable = true
		}
	}
	if st.PublicURL == "" {
		v.RedirectURI = ""
	}
	return v, nil
}

// Save stores cfg. A nil secret keeps the saved one, but only for the same
// tenant and app: pointing the settings at a different app needs its secret
// typed again, so the saved one is never sent somewhere else. A config with no
// tenant clears everything.
func (s *Service) Save(ctx context.Context, cfg Config, clientSecret *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg = cfg.normalize()
	if cfg.TenantID == "" && cfg.ClientID == "" {
		if err := s.refuseIfLockout(ctx); err != nil {
			return err
		}
		s.tokMu.Lock()
		s.tokens = nil
		s.tokMu.Unlock()
		if err := s.store.SetSetting(ctx, settingKey, ""); err != nil {
			return err
		}
		return s.endMicrosoftSessions(ctx)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	old, err := s.load(ctx)
	if err != nil {
		old = stored{}
	}
	if clientSecret == nil && old.Secret != "" && !old.Config.sameApp(cfg) {
		return InputError("You changed the tenant or the app, so enter the client secret again. The saved secret is only used with the app it was saved for.")
	}
	next := stored{Config: cfg, Secret: old.Secret, Disabled: old.Disabled}
	if clientSecret != nil {
		next.Secret = ""
		if v := strings.TrimSpace(*clientSecret); v != "" {
			if next.Secret, err = s.box.Seal(v); err != nil {
				return err
			}
		}
	}
	if next.Secret == "" {
		return InputError("Enter the client secret (the Value of a secret you created for the app).")
	}
	return s.save(ctx, next)
}

// resolve returns the config and plain client secret to use: cfg and
// clientSecret if given (for testing a form), else the saved ones.
func (s *Service) resolve(ctx context.Context, cfg *Config, clientSecret *string) (Config, string, error) {
	st, err := s.load(ctx)
	if err != nil {
		st = stored{}
	}
	use, sealed := st.Config, st.Secret
	if cfg != nil {
		use = cfg.normalize()
		if !st.Config.sameApp(use) && clientSecret == nil {
			return Config{}, "", InputError("To test a different app, enter its client secret. The saved secret is only used with the app it was saved for.")
		}
	}
	if clientSecret != nil {
		sealed = ""
	}
	plain := ""
	if clientSecret != nil {
		plain = strings.TrimSpace(*clientSecret)
	} else if sealed != "" {
		if plain, err = s.box.Open(sealed); err != nil {
			return Config{}, "", InputError("The saved client secret can't be read by this server (the settings may have come from a backup). Enter the client secret again and save.")
		}
	}
	if use.TenantID == "" {
		return Config{}, "", InputError("Entra isn't set up yet. Save the settings first.")
	}
	if plain == "" {
		return Config{}, "", InputError("Enter the client secret.")
	}
	return use, plain, nil
}

// --- The Integrations page's view ---

// ID is the integration's id.
func (s *Service) ID() string { return "entra" }

// Name is what the page calls it.
func (s *Service) Name() string { return "Microsoft Entra ID" }

// Description says what it is for.
func (s *Service) Description() string {
	return "Let the people in an Entra group sign in to SIEMLite with their Microsoft account."
}

// Info reports the card's state.
func (s *Service) Info(ctx context.Context) (integrations.Info, error) {
	v, err := s.Get(ctx)
	if err != nil {
		return integrations.Info{}, err
	}
	info := integrations.Info{Configured: v.Configured, Enabled: v.Enabled}
	if v.Configured {
		info.Summary = "Members of the access group can sign in with Microsoft."
		if v.SecretUnreadable {
			info.Summary = "The saved client secret can't be read on this server; enter it again."
		} else if ls := v.LastSync; ls != nil {
			when := time.UnixMilli(ls.At).Format("15:04")
			if ls.OK {
				info.Summary += fmt.Sprintf(" Last check %s: %d in the group, %d accounts.", when, ls.Members, ls.Accounts)
			} else {
				info.Summary += fmt.Sprintf(" The last check (%s) failed: %s", when, ls.Error)
			}
		}
	}
	return info, nil
}

// refuseIfLockout guards turning the integration off or removing it, which
// also ends every Microsoft session so that it takes effect now. It refuses if
// the only enabled admins are Microsoft accounts and no local admin exists:
// they would be signed out with no way back in.
func (s *Service) refuseIfLockout(ctx context.Context) error {
	sso, err := s.repo.CountEnabledAdmins(ctx, Provider)
	if err != nil {
		return err
	}
	if sso > 0 {
		local, err := s.repo.CountEnabledAdmins(ctx, storage.ProviderLocal)
		if err != nil {
			return err
		}
		if local == 0 {
			return InputError("The only admins sign in with Microsoft, so turning this off would lock everyone out. Create a local admin account first (Users page, or `siemlite users create -role admin`).")
		}
	}
	return nil
}

// SetEnabled turns single sign-on on or off without touching the settings.
// Turning it off also signs out everyone who signed in with Microsoft.
func (s *Service) SetEnabled(ctx context.Context, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	if st.TenantID == "" || st.Secret == "" {
		return InputError("Set up the Entra app first.")
	}
	if !on && !st.Disabled {
		if err := s.refuseIfLockout(ctx); err != nil {
			return err
		}
	}
	st.Disabled = !on
	if err := s.save(ctx, st); err != nil {
		return err
	}
	if !on {
		return s.endMicrosoftSessions(ctx)
	}
	return nil
}

func (s *Service) endMicrosoftSessions(ctx context.Context) error {
	n, err := s.repo.DeleteSessionsByProvider(ctx, Provider)
	if err != nil {
		return err
	}
	if n > 0 {
		s.log.Warn("single sign-on switched off: Microsoft sessions ended", "sessions", n)
	}
	return nil
}

// Active reports whether sign-in with Microsoft is on, for the sign-in page.
func (s *Service) Active(ctx context.Context) bool {
	v, err := s.Get(ctx)
	return err == nil && v.Enabled
}

// --- Test ---

// TestResult is what a successful connection test found.
type TestResult struct {
	AccessGroup        string `json:"access_group"`
	AccessGroupMembers int    `json:"access_group_members"`
	AdminGroup         string `json:"admin_group,omitempty"`
	AdminGroupMembers  int    `json:"admin_group_members,omitempty"`
	RedirectURI        string `json:"redirect_uri"`
}

// Test checks the form's settings (or the saved ones) against Entra without
// saving: the app can get a token, and read the group(s).
func (s *Service) Test(ctx context.Context, cfg *Config, clientSecret *string) (*TestResult, error) {
	if cfg != nil {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
	}
	use, plain, err := s.resolve(ctx, cfg, clientSecret)
	if err != nil {
		return nil, err
	}
	tok, err := s.appToken(ctx, use, plain)
	if err != nil {
		return nil, err
	}
	res := &TestResult{RedirectURI: use.RedirectURI()}
	for _, g := range []struct {
		id    string
		name  *string
		count *int
	}{{use.AccessGroupID, &res.AccessGroup, &res.AccessGroupMembers}, {use.AdminGroupID, &res.AdminGroup, &res.AdminGroupMembers}} {
		if g.id == "" {
			continue
		}
		if *g.name, err = s.groupName(ctx, tok, g.id); err != nil {
			return nil, err
		}
		m, err := s.members(ctx, tok, g.id)
		if err != nil {
			return nil, err
		}
		*g.count = len(m)
	}
	return res, nil
}

// --- Sign-in ---

type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"x"`
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ErrNotActive means sign-in with Microsoft isn't set up and turned on.
var ErrNotActive = errors.New("sign-in with Microsoft isn't turned on")

// BeginLogin starts a sign-in. It returns the Microsoft address to send the
// browser to, and the (sealed) value for a short-lived cookie that remembers
// this sign-in until Microsoft sends the person back.
func (s *Service) BeginLogin(ctx context.Context) (authURL, flowCookie string, err error) {
	st, err := s.load(ctx)
	if err != nil {
		return "", "", err
	}
	if st.TenantID == "" || st.Secret == "" || st.Disabled {
		return "", "", ErrNotActive
	}
	f := flow{Expires: time.Now().Add(flowTTL).Unix()}
	for _, p := range []*string{&f.State, &f.Nonce, &f.Verifier} {
		if *p, err = randomString(32); err != nil {
			return "", "", err
		}
	}
	if flowCookie, err = func() (string, error) { b, _ := json.Marshal(f); return s.box.Seal(string(b)) }(); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(f.Verifier))
	q := url.Values{
		"client_id": {st.ClientID}, "response_type": {"code"}, "redirect_uri": {st.Config.RedirectURI()},
		"response_mode": {"query"}, "scope": {"openid profile"}, "state": {f.State}, "nonce": {f.Nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"prompt": {"select_account"},
	}
	return s.authority() + "/" + st.TenantID + "/oauth2/v2.0/authorize?" + q.Encode(), flowCookie, nil
}

// CompleteLogin finishes a sign-in: it checks that Microsoft's answer belongs
// to the sign-in that was started, verifies who the person is, confirms they
// are in the access group, and returns their SIEMLite account (creating it the
// first time). The caller then starts the session.
func (s *Service) CompleteLogin(ctx context.Context, code, state, flowCookie string) (*storage.User, error) {
	st, err := s.load(ctx)
	if err != nil {
		return nil, failed("read settings: %v", err)
	}
	if st.TenantID == "" || st.Secret == "" || st.Disabled {
		return nil, failed("not turned on")
	}
	var f flow
	plain, err := s.box.Open(flowCookie)
	if err != nil || json.Unmarshal([]byte(plain), &f) != nil || f.State == "" {
		return nil, &LoginError{CodeExpired, "no sign-in in progress for this browser"}
	}
	if time.Now().Unix() > f.Expires {
		return nil, &LoginError{CodeExpired, "the sign-in took too long"}
	}
	if code == "" || subtle.ConstantTimeCompare([]byte(state), []byte(f.State)) != 1 {
		return nil, failed("the state doesn't match this sign-in")
	}
	clientSecret, err := s.box.Open(st.Secret)
	if err != nil {
		return nil, failed("the client secret can't be read")
	}

	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := s.tokenRequest(ctx, st.Config, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {st.ClientID}, "client_secret": {clientSecret},
		"code": {code}, "redirect_uri": {st.Config.RedirectURI()}, "code_verifier": {f.Verifier}, "scope": {"openid profile"},
	}, &tok); err != nil {
		return nil, failed("exchange the code: %v", err)
	}
	c, err := s.verifyIDToken(ctx, tok.IDToken, st.Config, f.Nonce, time.Now())
	if err != nil {
		return nil, failed("verify the ID token: %v", err)
	}
	username := strings.ToLower(strings.TrimSpace(c.Username))
	if username == "" {
		username = strings.ToLower(strings.TrimSpace(c.Email))
	}
	if username == "" || len(username) > 64 || strings.ContainsAny(username, " \t\r\n") {
		return nil, failed("the account has no usable user name (%q)", username)
	}

	// Who may sign in is decided by the directory, now, not by the token.
	gt, err := s.appToken(ctx, st.Config, clientSecret)
	if err != nil {
		return nil, failed("get a Graph token: %v", err)
	}
	in, err := s.isMember(ctx, gt, st.AccessGroupID, c.ObjectID)
	if err != nil {
		return nil, failed("check the access group: %v", err)
	}
	if !in {
		return nil, &LoginError{CodeNotInGroup, username + " is not in the access group"}
	}
	admin := false
	if st.AdminGroupID != "" {
		if admin, err = s.isMember(ctx, gt, st.AdminGroupID, c.ObjectID); err != nil {
			return nil, failed("check the admin group: %v", err)
		}
	}
	role := "standard"
	if admin {
		role = "admin"
	}

	u, err := s.repo.FindExternalUser(ctx, Provider, c.ObjectID)
	switch {
	case errors.Is(err, storage.ErrUserNotFound):
		id, cerr := s.repo.CreateExternalUser(ctx, Provider, c.ObjectID, username, role, time.Now().UnixMilli())
		if errors.Is(cerr, storage.ErrUserExists) {
			return nil, &LoginError{CodeNameTaken, "an account named " + username + " already exists"}
		}
		if cerr != nil {
			return nil, failed("create the account: %v", cerr)
		}
		if u, err = s.repo.GetUser(ctx, id); err != nil {
			return nil, failed("read the new account: %v", err)
		}
		s.log.Info("single sign-on account created", "user", username, "role", role)
	case err != nil:
		return nil, failed("find the account: %v", err)
	default:
		if u.Disabled { // they are in the group again
			if err := s.repo.SetUserDisabled(ctx, u.ID, false); err != nil {
				return nil, failed("re-enable the account: %v", err)
			}
		}
		if st.AdminGroupID != "" && u.Role != role {
			if err := s.repo.UpdateUserAccess(ctx, u.ID, role, u.Limited, u.Sources); err != nil {
				s.log.Warn("couldn't change a single sign-on user's role", "user", u.Username, "to", role, "err", err)
			}
		}
		if u, err = s.repo.GetUser(ctx, u.ID); err != nil {
			return nil, failed("read the account: %v", err)
		}
	}
	return u, nil
}

// --- Sync ---

// Sync checks the access group against the accounts that sign in with
// Microsoft: people who have left it (or whose Microsoft account is disabled)
// are switched off and signed out, people who are back are switched on, and,
// if there is an admin group, roles follow it. Nothing is changed unless the
// whole member list was read.
func (s *Service) Sync(ctx context.Context) (SyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stat := SyncStatus{At: time.Now().UnixMilli()}
	finish := func(err error) (SyncStatus, error) {
		if err != nil {
			stat.Error = err.Error()
		} else {
			stat.OK = true
		}
		s.lastSync = &stat
		if b, merr := json.Marshal(stat); merr == nil {
			_ = s.store.SetSetting(ctx, syncSettingKey, string(b))
		}
		return stat, err
	}
	st, err := s.load(ctx)
	if err != nil {
		return finish(err)
	}
	if st.TenantID == "" || st.Secret == "" || st.Disabled {
		return stat, ErrNotActive
	}
	clientSecret, err := s.box.Open(st.Secret)
	if err != nil {
		return finish(errors.New("the saved client secret can't be read"))
	}
	tok, err := s.appToken(ctx, st.Config, clientSecret)
	if err != nil {
		return finish(err)
	}
	access, err := s.members(ctx, tok, st.AccessGroupID)
	if err != nil {
		return finish(err)
	}
	admins := map[string]bool{}
	if st.AdminGroupID != "" {
		if admins, err = s.members(ctx, tok, st.AdminGroupID); err != nil {
			return finish(err)
		}
	}
	for _, ok := range access {
		if ok {
			stat.Members++
		}
	}
	users, err := s.repo.ListExternalUsers(ctx, Provider)
	if err != nil {
		return finish(err)
	}
	stat.Accounts = len(users)
	for _, u := range users {
		allowed := access[u.ExternalID]
		switch {
		case !allowed && !u.Disabled:
			if err := s.repo.SetUserDisabled(ctx, u.ID, true); err != nil {
				if errors.Is(err, storage.ErrLastAdmin) {
					stat.Protected++
					s.log.Warn("single sign-on user is no longer in the access group but is the last enabled admin, so was kept: create another admin",
						"user", u.Username)
				} else {
					s.log.Warn("couldn't switch off a single sign-on user", "user", u.Username, "err", err)
				}
				continue
			}
			stat.Disabled++
			s.log.Warn("single sign-on user switched off: no longer in the access group", "user", u.Username)
		case allowed && u.Disabled:
			if err := s.repo.SetUserDisabled(ctx, u.ID, false); err != nil {
				s.log.Warn("couldn't switch on a single sign-on user", "user", u.Username, "err", err)
				continue
			}
			stat.Enabled++
		}
		if allowed && st.AdminGroupID != "" {
			want := "standard"
			if admins[u.ExternalID] {
				want = "admin"
			}
			if u.Role != want {
				if err := s.repo.UpdateUserAccess(ctx, u.ID, want, u.Limited, u.Sources); err != nil {
					s.log.Warn("couldn't change a single sign-on user's role", "user", u.Username, "to", want, "err", err)
					continue
				}
				stat.Changed++
			}
		}
	}
	return finish(nil)
}

// Run checks membership every SyncEvery until ctx ends, while sign-in is on.
func (s *Service) Run(ctx context.Context) {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if s.Active(ctx) {
			if _, err := s.Sync(ctx); err != nil && !errors.Is(err, ErrNotActive) {
				s.log.Warn("Entra membership check failed", "err", err)
			}
		}
		timer.Reset(SyncEvery)
	}
}
