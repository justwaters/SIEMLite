package entra

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/entra/entratest"
	"siemlite/pkg/storage"
)

const (
	ann  = "0000000a-0000-0000-0000-000000000001"
	bob  = "0000000b-0000-0000-0000-000000000002"
	cara = "0000000c-0000-0000-0000-000000000003"
)

func TestConfigValidate(t *testing.T) {
	ok := Config{TenantID: tenant, ClientID: clientID, PublicURL: "https://siem.example.com", AccessGroupID: accessGroup}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := ok.RedirectURI(); got != "https://siem.example.com/api/v1/auth/entra/callback" {
		t.Errorf("redirect = %s", got)
	}
	withPort := ok
	withPort.PublicURL = "https://siem.example.com:8443/"
	if withPort.Validate() != nil || withPort.RedirectURI() != "https://siem.example.com:8443/api/v1/auth/entra/callback" {
		t.Errorf("port + trailing slash: %v %s", withPort.Validate(), withPort.RedirectURI())
	}
	for name, mod := range map[string]func(*Config){
		"tenant name":        func(c *Config) { c.TenantID = "contoso.onmicrosoft.com" },
		"tenant common":      func(c *Config) { c.TenantID = "common" },
		"tenant empty":       func(c *Config) { c.TenantID = "" },
		"client":             func(c *Config) { c.ClientID = "not-a-guid" },
		"http url":           func(c *Config) { c.PublicURL = "http://siem.example.com" },
		"url with path":      func(c *Config) { c.PublicURL = "https://siem.example.com/siem" },
		"url with query":     func(c *Config) { c.PublicURL = "https://siem.example.com/?x=1" },
		"url with user":      func(c *Config) { c.PublicURL = "https://u:p@siem.example.com" },
		"url without scheme": func(c *Config) { c.PublicURL = "siem.example.com" },
		"access group":       func(c *Config) { c.AccessGroupID = "Everyone" },
		"admin group":        func(c *Config) { c.AdminGroupID = "Admins" },
	} {
		c := ok
		mod(&c)
		var bad InputError
		if err := c.Validate(); !errors.As(err, &bad) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	upper := ok
	upper.TenantID = strings.ToUpper(tenant)
	if upper.Validate() != nil {
		t.Error("upper-case GUIDs should be fine")
	}
}

func TestSignInCreatesAndRemembersAnAccount(t *testing.T) {
	e := newEnv(t)
	e.ms.Set(accessGroup, ann, true)

	u, err := e.signIn(strings.ToUpper(ann), "Ann@Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "ann@example.com" || u.Role != "standard" || u.AuthProvider != "entra" || u.ExternalID != ann || u.Disabled || u.Limited {
		t.Fatalf("new account = %+v", u)
	}
	// The same person is the same account, even if their name changed.
	again, err := e.signIn(ann, "ann.renamed@example.com")
	if err != nil || again.ID != u.ID || again.Username != "ann@example.com" {
		t.Errorf("second sign-in = %+v %v", again, err)
	}
	if list, _ := e.repo.ListExternalUsers(bg(), "entra"); len(list) != 1 {
		t.Errorf("%d accounts", len(list))
	}
}

func TestSignInRefusals(t *testing.T) {
	e := newEnv(t)
	e.ms.Set(accessGroup, ann, true)

	// Not in the group.
	if _, err := e.signIn(bob, "bob@example.com"); code(err) != CodeNotInGroup {
		t.Errorf("non-member: %v", err)
	}
	if _, err := e.repo.FindExternalUser(bg(), "entra", bob); !errors.Is(err, storage.ErrUserNotFound) {
		t.Error("an account was made for someone outside the group")
	}
	// A name already used by a local account is never taken over.
	e.repo.CreateUser(bg(), "ann@example.com", "hash", "admin", 1)
	if _, err := e.signIn(ann, "ann@example.com"); code(err) != CodeNameTaken {
		t.Errorf("name taken: %v", err)
	}
	if _, err := e.repo.FindExternalUser(bg(), "entra", ann); !errors.Is(err, storage.ErrUserNotFound) {
		t.Error("the existing account was linked to the Microsoft identity")
	}
	// A user name that can't be an account name.
	e.ms.Set(accessGroup, cara, true)
	for _, upn := range []string{"", "has space@example.com", strings.Repeat("x", 70) + "@example.com"} {
		if _, err := e.signIn(cara, upn); code(err) != CodeFailed {
			t.Errorf("user name %q: %v", upn, err)
		}
	}
	// Turned off.
	if err := e.svc.SetEnabled(bg(), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.BeginLogin(bg()); !errors.Is(err, ErrNotActive) {
		t.Errorf("BeginLogin while off: %v", err)
	}
	if e.svc.Active(bg()) {
		t.Error("Active while off")
	}
}

func TestSignInRejectsBadTokens(t *testing.T) {
	e := newEnv(t)
	e.ms.Set(accessGroup, ann, true)
	other := entratest.RSAKey(t)

	for name, mod := range map[string]func(){
		"signed by another key":  func() { e.ms.Opts.OtherKey = other },
		"wrong audience":         func() { e.ms.Opts.Aud = "ffffffff-ffff-ffff-ffff-ffffffffffff" },
		"wrong tenant":           func() { e.ms.Opts.Tid = "ffffffff-ffff-ffff-ffff-ffffffffffff" },
		"wrong issuer":           func() { e.ms.Opts.Iss = "https://evil.example/" + tenant + "/v2.0" },
		"expired":                func() { e.ms.Opts.Expired = true },
		"HS256 instead of RS256": func() { e.ms.Opts.HS256 = true },
		"no nonce":               func() { e.ms.Opts.NoNonce = true },
	} {
		e.ms.Opts = entratest.TokenOptions{}
		mod()
		u, err := e.signIn(ann, "ann@example.com")
		if code(err) != CodeFailed || u != nil {
			t.Errorf("%s accepted: %+v %v", name, u, err)
		}
	}
	if list, _ := e.repo.ListExternalUsers(bg(), "entra"); len(list) != 0 {
		t.Errorf("a rejected token still created %d accounts", len(list))
	}
}

func TestSignInFlowIsBoundToTheBrowser(t *testing.T) {
	e := newEnv(t)
	e.ms.Set(accessGroup, ann, true)
	authURL, cookie, err := e.svc.BeginLogin(bg())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("scope") != "openid profile" ||
		q.Get("redirect_uri") != "https://siem.example.com:8443/api/v1/auth/entra/callback" || q.Get("client_id") != clientID ||
		!strings.HasPrefix(authURL, e.ms.URL+"/"+tenant+"/oauth2/v2.0/authorize?") {
		t.Errorf("authorize URL = %s", authURL)
	}
	if strings.Contains(cookie, q.Get("state")) || strings.Contains(cookie, q.Get("nonce")) {
		t.Error("the flow cookie shows its contents")
	}
	e.ms.Expect(authURL, ann, "ann@example.com")

	if _, err := e.svc.CompleteLogin(bg(), entratest.Code, "wrong-state", cookie); code(err) != CodeFailed {
		t.Errorf("wrong state: %v", err)
	}
	if _, err := e.svc.CompleteLogin(bg(), entratest.Code, q.Get("state"), "garbage"); code(err) != CodeExpired {
		t.Errorf("garbage cookie: %v", err)
	}
	if _, err := e.svc.CompleteLogin(bg(), entratest.Code, q.Get("state"), ""); code(err) != CodeExpired {
		t.Errorf("no cookie: %v", err)
	}
	if _, err := e.svc.CompleteLogin(bg(), "", q.Get("state"), cookie); code(err) != CodeFailed {
		t.Errorf("no code: %v", err)
	}
	if _, err := e.svc.CompleteLogin(bg(), "bad-code", q.Get("state"), cookie); code(err) != CodeFailed {
		t.Errorf("rejected code: %v", err)
	}
	// An expired flow.
	old := flow{State: q.Get("state"), Nonce: q.Get("nonce"), Verifier: "v", Expires: time.Now().Add(-time.Minute).Unix()}
	b, _ := json.Marshal(old)
	stale, _ := e.box.Seal(string(b))
	if _, err := e.svc.CompleteLogin(bg(), entratest.Code, q.Get("state"), stale); code(err) != CodeExpired {
		t.Errorf("expired flow: %v", err)
	}
	// A flow cookie from another server's key is worthless.
	otherSvc := newEnv(t)
	_, foreign, _ := otherSvc.svc.BeginLogin(bg())
	if _, err := e.svc.CompleteLogin(bg(), entratest.Code, q.Get("state"), foreign); code(err) != CodeExpired {
		t.Errorf("another server's cookie: %v", err)
	}
	// The real one still works once.
	if u, err := e.svc.CompleteLogin(bg(), entratest.Code, q.Get("state"), cookie); err != nil || u == nil {
		t.Errorf("the genuine sign-in: %v", err)
	}
}

func TestAdminGroupSetsTheRole(t *testing.T) {
	e := newEnv(t)
	cfg := e.cfg
	cfg.AdminGroupID = adminGroup
	if err := e.svc.Save(bg(), cfg, nil); err != nil {
		t.Fatal(err)
	}
	e.ms.Set(accessGroup, ann, true)
	e.ms.Set(accessGroup, bob, true)
	e.ms.Set(adminGroup, ann, true)

	a, err := e.signIn(ann, "ann@example.com")
	if err != nil || a.Role != "admin" {
		t.Fatalf("admin-group member = %+v %v", a, err)
	}
	b, err := e.signIn(bob, "bob@example.com")
	if err != nil || b.Role != "standard" {
		t.Fatalf("everyone else = %+v %v", b, err)
	}
	// Leaving the admin group demotes at the next sign-in (another admin exists).
	e.repo.CreateUser(bg(), "root", "h", "admin", 1)
	e.ms.Remove(adminGroup, ann)
	if a, err = e.signIn(ann, "ann@example.com"); err != nil || a.Role != "standard" {
		t.Errorf("demoted = %+v %v", a, err)
	}
	// Joining it promotes, and a limit set on the account is kept.
	e.repo.UpdateUserAccess(bg(), b.ID, "standard", true, nil)
	e.ms.Set(adminGroup, bob, true)
	if b, err = e.signIn(bob, "bob@example.com"); err != nil || b.Role != "admin" {
		t.Errorf("promoted = %+v %v", b, err)
	}
}

func TestWithoutAnAdminGroupRolesAreLeftAlone(t *testing.T) {
	e := newEnv(t)
	e.ms.Set(accessGroup, ann, true)
	a, err := e.signIn(ann, "ann@example.com")
	if err != nil || a.Role != "standard" {
		t.Fatal(a, err)
	}
	e.repo.UpdateUserAccess(bg(), a.ID, "admin", false, nil) // an admin promoted her by hand
	if a, err = e.signIn(ann, "ann@example.com"); err != nil || a.Role != "admin" {
		t.Errorf("a role set by hand was overwritten: %+v %v", a, err)
	}
}

func TestSyncSwitchesPeopleOffAndOn(t *testing.T) {
	e := newEnv(t)
	cfg := e.cfg
	cfg.AdminGroupID = adminGroup
	e.svc.Save(bg(), cfg, nil)
	e.repo.CreateUser(bg(), "root", "h", "admin", 1)
	for _, p := range []struct{ oid, name string }{{ann, "ann@example.com"}, {bob, "bob@example.com"}, {cara, "cara@example.com"}} {
		e.ms.Set(accessGroup, p.oid, true)
		if _, err := e.signIn(p.oid, p.name); err != nil {
			t.Fatal(err)
		}
	}
	annU, _ := e.repo.FindExternalUser(bg(), "entra", ann)
	e.repo.CreateSession(bg(), "ann-session", annU.ID, 1, 1<<50)

	// Nothing changed yet.
	st, err := e.svc.Sync(bg())
	if err != nil || !st.OK || st.Members != 3 || st.Accounts != 3 || st.Disabled+st.Enabled+st.Changed != 0 {
		t.Fatalf("quiet sync = %+v %v", st, err)
	}

	// Ann leaves, Bob's Microsoft account is disabled, Cara becomes an admin.
	e.ms.Remove(accessGroup, ann)
	e.ms.Set(accessGroup, bob, false)
	e.ms.Set(adminGroup, cara, true)
	st, err = e.svc.Sync(bg())
	if err != nil || st.Disabled != 2 || st.Changed != 1 || st.Members != 1 {
		t.Fatalf("sync = %+v %v", st, err)
	}
	for oid, want := range map[string]bool{ann: true, bob: true, cara: false} {
		u, _ := e.repo.FindExternalUser(bg(), "entra", oid)
		if u.Disabled != want {
			t.Errorf("%s disabled = %v, want %v", u.Username, u.Disabled, want)
		}
	}
	if c, _ := e.repo.FindExternalUser(bg(), "entra", cara); c.Role != "admin" {
		t.Errorf("cara's role = %s", c.Role)
	}
	if _, err := e.repo.FindSession(bg(), "ann-session", 2); !errors.Is(err, storage.ErrUserNotFound) {
		t.Error("a removed person's session still works")
	}
	if _, err := e.signIn(ann, "ann@example.com"); code(err) != CodeNotInGroup {
		t.Errorf("a removed person signed in: %v", err)
	}

	// They come back: switched on by the next sync, or at their next sign-in.
	e.ms.Set(accessGroup, ann, true)
	e.ms.Set(accessGroup, bob, true)
	if st, err = e.svc.Sync(bg()); err != nil || st.Enabled != 2 {
		t.Fatalf("sync back = %+v %v", st, err)
	}
	if u, _ := e.repo.FindExternalUser(bg(), "entra", ann); u.Disabled {
		t.Error("ann still disabled")
	}
	e.ms.Remove(accessGroup, bob)
	e.svc.Sync(bg())
	e.ms.Set(accessGroup, bob, true)
	if u, err := e.signIn(bob, "bob@example.com"); err != nil || u.Disabled {
		t.Errorf("signing in re-enables: %+v %v", u, err)
	}
	// The status is kept for the page.
	if v, _ := e.svc.Get(bg()); v.LastSync == nil || !v.LastSync.OK {
		t.Errorf("last sync = %+v", v.LastSync)
	}
}

func TestSyncNeverRemovesTheLastAdmin(t *testing.T) {
	e := newEnv(t)
	cfg := e.cfg
	cfg.AdminGroupID = adminGroup
	e.svc.Save(bg(), cfg, nil)
	e.ms.Set(accessGroup, ann, true)
	e.ms.Set(adminGroup, ann, true)
	a, err := e.signIn(ann, "ann@example.com") // the only admin
	if err != nil || a.Role != "admin" {
		t.Fatal(a, err)
	}
	e.ms.Remove(accessGroup, ann)
	e.ms.Remove(adminGroup, ann)
	if _, err := e.svc.Sync(bg()); err != nil {
		t.Fatal(err)
	}
	if u, _ := e.repo.FindExternalUser(bg(), "entra", ann); u.Disabled || u.Role != "admin" {
		t.Errorf("the last admin was switched off or demoted: %+v", u)
	}
}

func TestSyncChangesNothingWhenMicrosoftFails(t *testing.T) {
	e := newEnv(t)
	e.ms.Set(accessGroup, ann, true)
	if _, err := e.signIn(ann, "ann@example.com"); err != nil {
		t.Fatal(err)
	}
	e.repo.CreateUser(bg(), "root", "h", "admin", 1)
	e.ms.Remove(accessGroup, ann) // she has left, but Graph is failing, so nobody can know
	e.ms.GraphStatus = 500
	st, err := e.svc.Sync(bg())
	if err == nil || st.OK || st.Error == "" {
		t.Fatalf("sync = %+v %v", st, err)
	}
	if u, _ := e.repo.FindExternalUser(bg(), "entra", ann); u.Disabled {
		t.Error("someone was switched off on an incomplete answer")
	}
	// Missing permission is explained.
	e.ms.GraphStatus = 403
	if _, err := e.svc.Sync(bg()); err == nil || !strings.Contains(err.Error(), "GroupMember.Read.All") {
		t.Errorf("403: %v", err)
	}
	if v, _ := e.svc.Get(bg()); v.LastSync == nil || v.LastSync.OK {
		t.Errorf("failure not recorded: %+v", v.LastSync)
	}
	e.ms.GraphStatus = 0
	if st, err := e.svc.Sync(bg()); err != nil || st.Disabled != 1 {
		t.Errorf("recovered sync = %+v %v", st, err)
	}
}

func TestSyncReadsEveryPageAndRefusesForeignLinks(t *testing.T) {
	e := newEnv(t)
	e.ms.PageSize = 2
	var oids []string
	for i := 0; i < 7; i++ {
		oid := "0000000" + string(rune('a'+i)) + "-0000-0000-0000-00000000000" + string(rune('1'+i))
		oids = append(oids, oid)
		e.ms.Set(accessGroup, oid, true)
	}
	st, err := e.svc.Sync(bg())
	if err != nil || st.Members != 7 {
		t.Fatalf("paged sync = %+v %v", st, err)
	}
	// A link to another host is not followed (it would receive the token).
	e.ms.NextLinkHost = "https://evil.example"
	if _, err := e.svc.Sync(bg()); err == nil || !strings.Contains(err.Error(), "another site") {
		t.Errorf("foreign nextLink: %v", err)
	}
}

func TestTestConnection(t *testing.T) {
	e := newEnv(t)
	e.ms.Set(accessGroup, ann, true)
	e.ms.Set(accessGroup, bob, true)
	cfg := e.cfg
	cfg.AdminGroupID = adminGroup
	e.ms.Set(adminGroup, ann, true)

	res, err := e.svc.Test(bg(), &cfg, nil) // saved secret, same app
	if err != nil || res.AccessGroup == "" || res.AccessGroupMembers != 2 || res.AdminGroupMembers != 1 || !strings.HasSuffix(res.RedirectURI, "/api/v1/auth/entra/callback") {
		t.Fatalf("test = %+v %v", res, err)
	}
	bad := "wrong-secret"
	if _, err := e.svc.Test(bg(), &cfg, &bad); err == nil || !strings.Contains(err.Error(), "client secret") {
		t.Errorf("wrong secret: %v", err)
	}
	// The saved secret is never tried against another app.
	elsewhere := cfg
	elsewhere.ClientID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
	var in InputError
	if _, err := e.svc.Test(bg(), &elsewhere, nil); !errors.As(err, &in) {
		t.Errorf("saved secret used for another app: %v", err)
	}
	missing := cfg
	missing.AccessGroupID = "99999999-0000-0000-0000-0000000000ff"
	if _, err := e.svc.Test(bg(), &missing, nil); err == nil || !strings.Contains(err.Error(), "couldn't find that group") {
		t.Errorf("missing group: %v", err)
	}
	invalid := cfg
	invalid.TenantID = "nope"
	if _, err := e.svc.Test(bg(), &invalid, nil); !errors.As(err, &in) {
		t.Errorf("invalid config: %v", err)
	}
}

func TestSettingsAndTheSecret(t *testing.T) {
	e := newEnv(t)
	if strings.Contains(e.st.m[settingKey], clientPass) {
		t.Fatalf("the secret is stored in the clear: %s", e.st.m[settingKey])
	}
	v, _ := e.svc.Get(bg())
	if !v.Configured || !v.Enabled || !v.HasSecret || v.SecretUnreadable || v.RedirectURI == "" {
		t.Errorf("view = %+v", v)
	}
	if b, _ := json.Marshal(v); strings.Contains(string(b), clientPass) || strings.Contains(string(b), "v1:") {
		t.Errorf("the secret is in the view: %s", b)
	}
	var in InputError
	// Another app needs its own secret; the same app keeps it.
	other := e.cfg
	other.ClientID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
	if err := e.svc.Save(bg(), other, nil); !errors.As(err, &in) {
		t.Errorf("secret carried to another app: %v", err)
	}
	same := e.cfg
	same.AccessGroupID = "99999999-0000-0000-0000-0000000000aa"
	if err := e.svc.Save(bg(), same, nil); err != nil {
		t.Errorf("changing only the group: %v", err)
	}
	// A secret is required.
	empty := ""
	if err := e.svc.Save(bg(), same, &empty); !errors.As(err, &in) {
		t.Errorf("empty secret: %v", err)
	}
	// On and off keep the settings.
	if err := e.svc.SetEnabled(bg(), false); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.svc.Get(bg()); !v.Configured || v.Enabled {
		t.Errorf("off view = %+v", v)
	}
	info, _ := e.svc.Info(bg())
	if !info.Configured || info.Enabled || e.svc.ID() != "entra" || e.svc.Name() == "" {
		t.Errorf("off info = %+v", info)
	}
	if _, err := e.svc.Sync(bg()); !errors.Is(err, ErrNotActive) {
		t.Errorf("sync while off: %v", err)
	}
	// A server with another key can't read the secret, and says so.
	foreign := NewService(e.st, e.repo, newEnv(t).box, nil)
	if v, _ := foreign.Get(bg()); !v.SecretUnreadable {
		t.Errorf("foreign key view = %+v", v)
	}
	if _, err := foreign.Test(bg(), nil, nil); !errors.As(err, &in) || !strings.Contains(err.Error(), "can't be read") {
		t.Errorf("foreign key test: %v", err)
	}
	// Removing the settings.
	if err := e.svc.Save(bg(), Config{}, nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.svc.Get(bg()); v.Configured || v.TenantID != "" {
		t.Errorf("not cleared: %+v", v)
	}
	if err := e.svc.SetEnabled(bg(), true); !errors.As(err, &in) {
		t.Errorf("turning on with nothing saved: %v", err)
	}
}

func TestTurningOffSignsMicrosoftAccountsOut(t *testing.T) {
	e := newEnv(t)
	cfg := e.cfg
	cfg.AdminGroupID = adminGroup
	e.svc.Save(bg(), cfg, nil)
	e.ms.Set(accessGroup, ann, true)
	e.ms.Set(accessGroup, bob, true)
	e.ms.Set(adminGroup, ann, true)
	a, err := e.signIn(ann, "ann@example.com") // an admin who signs in with Microsoft
	if err != nil || a.Role != "admin" {
		t.Fatal(a, err)
	}
	b, _ := e.signIn(bob, "bob@example.com")
	e.repo.CreateSession(bg(), "ann", a.ID, 1, 1<<50)
	e.repo.CreateSession(bg(), "bob", b.ID, 1, 1<<50)
	alive := func(tok string) bool { _, err := e.repo.FindSession(bg(), tok, 2); return err == nil }
	var in InputError

	// With no local admin, turning it off or removing it would lock everyone out: refused, nothing changes.
	if err := e.svc.SetEnabled(bg(), false); !errors.As(err, &in) || !strings.Contains(err.Error(), "lock everyone out") {
		t.Fatalf("turning off with only Microsoft admins: %v", err)
	}
	if err := e.svc.Save(bg(), Config{}, nil); !errors.As(err, &in) {
		t.Fatalf("removing with only Microsoft admins: %v", err)
	}
	if v, _ := e.svc.Get(bg()); !v.Enabled || !v.Configured {
		t.Errorf("a refused change took effect: %+v", v)
	}
	if !alive("ann") || !alive("bob") {
		t.Error("a refused change ended sessions")
	}

	// With a local admin (who has a session of their own), off ends every Microsoft session and only those.
	root, _ := e.repo.CreateUser(bg(), "root", "h", "admin", 1)
	e.repo.CreateSession(bg(), "root", root, 1, 1<<50)
	if err := e.svc.SetEnabled(bg(), false); err != nil {
		t.Fatal(err)
	}
	if alive("ann") || alive("bob") {
		t.Error("Microsoft sessions survived turning the integration off")
	}
	if !alive("root") {
		t.Error("a local session was ended")
	}
	if u, _ := e.repo.FindExternalUser(bg(), "entra", ann); u.Disabled || u.Role != "admin" {
		t.Errorf("the accounts should be kept as they were: %+v", u)
	}
	if _, err := e.signIn(bob, "bob@example.com"); !errors.Is(err, ErrNotActive) {
		t.Errorf("signing in while off: %v", err)
	}
	// Turning it on again lets them sign in again.
	if err := e.svc.SetEnabled(bg(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.signIn(bob, "bob@example.com"); err != nil {
		t.Errorf("signing in after turning it back on: %v", err)
	}

	// Removing it ends them too.
	e.repo.CreateSession(bg(), "bob2", b.ID, 1, 1<<50)
	if err := e.svc.Save(bg(), Config{}, nil); err != nil {
		t.Fatal(err)
	}
	if alive("bob2") {
		t.Error("a Microsoft session survived removing the integration")
	}
	if v, _ := e.svc.Get(bg()); v.Configured {
		t.Error("not removed")
	}
}

func TestTurningOffIsAllowedWithoutMicrosoftAdmins(t *testing.T) {
	e := newEnv(t) // no admin group, so everyone is Standard and nobody depends on Microsoft to administer
	e.ms.Set(accessGroup, bob, true)
	b, err := e.signIn(bob, "bob@example.com")
	if err != nil || b.Role != "standard" {
		t.Fatal(b, err)
	}
	e.repo.CreateSession(bg(), "bob", b.ID, 1, 1<<50)
	if err := e.svc.SetEnabled(bg(), false); err != nil {
		t.Fatalf("turning off with no Microsoft admins: %v", err)
	}
	if _, err := e.repo.FindSession(bg(), "bob", 2); err == nil {
		t.Error("the session survived")
	}
}

func TestSyncSaysWhoWasKeptBecauseTheyAreTheLastAdmin(t *testing.T) {
	e := newEnv(t)
	cfg := e.cfg
	cfg.AdminGroupID = adminGroup
	e.svc.Save(bg(), cfg, nil)
	e.ms.Set(accessGroup, ann, true)
	e.ms.Set(adminGroup, ann, true)
	if _, err := e.signIn(ann, "ann@example.com"); err != nil {
		t.Fatal(err)
	}
	e.ms.Remove(accessGroup, ann)
	e.ms.Remove(adminGroup, ann)
	st, err := e.svc.Sync(bg())
	if err != nil || st.Disabled != 0 || st.Protected != 1 {
		t.Fatalf("sync = %+v %v", st, err)
	}
	if v, _ := e.svc.Get(bg()); v.LastSync == nil || v.LastSync.Protected != 1 {
		t.Errorf("the status doesn't say: %+v", v.LastSync)
	}
	// Once another admin exists the next check switches her off.
	e.repo.CreateUser(bg(), "root", "h", "admin", 1)
	if st, err = e.svc.Sync(bg()); err != nil || st.Disabled != 1 || st.Protected != 0 {
		t.Errorf("sync with another admin = %+v %v", st, err)
	}
}
