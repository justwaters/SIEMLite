package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/auth"
	"siemlite/pkg/entra/entratest"
)

const (
	annOID  = "0000000a-0000-0000-0000-000000000001"
	bobOID  = "0000000b-0000-0000-0000-000000000002"
	caraOID = "0000000c-0000-0000-0000-000000000003"
)

func entraForm(e *env) map[string]any {
	return map[string]any{"tenant_id": entratest.Tenant, "client_id": entratest.ClientID, "client_secret": entratest.ClientSecret,
		"public_url": "https://siem.example.com:8443", "access_group_id": entratest.AccessGroup}
}

// browser is a client that doesn't follow redirects, so each step can be looked at.
func (e *env) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := *e.srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func (e *env) get(c *http.Client, path string) *http.Response {
	e.t.Helper()
	resp, err := c.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func setCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// startSSO runs the first step and returns Microsoft's address and the state in it.
func (e *env) startSSO(c *http.Client) (authURL, state string) {
	e.t.Helper()
	resp := e.get(c, "/api/v1/auth/entra/start")
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.HasPrefix(loc, e.ms.URL+"/"+entratest.Tenant+"/oauth2/v2.0/authorize?") {
		e.t.Fatalf("start = %d %q", resp.StatusCode, loc)
	}
	u, _ := url.Parse(loc)
	return loc, u.Query().Get("state")
}

func TestEntraSettingsAPI(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	e.ms.Set(entratest.AccessGroup, annOID, true)
	e.ms.Set(entratest.AccessGroup, bobOID, true)

	var v map[string]any
	if got := e.call(root, "GET", "/api/v1/integrations/entra", nil, &v, nil); got != 200 || v["configured"] != false {
		t.Fatalf("empty = %d %v", got, v)
	}
	// Mistakes are explained, and nothing is saved.
	for name, mod := range map[string]func(map[string]any){
		"tenant":    func(m map[string]any) { m["tenant_id"] = "contoso.com" },
		"client":    func(m map[string]any) { m["client_id"] = "x" },
		"http url":  func(m map[string]any) { m["public_url"] = "http://siem.example.com" },
		"group":     func(m map[string]any) { m["access_group_id"] = "Everyone" },
		"no secret": func(m map[string]any) { m["client_secret"] = "" },
		"long":      func(m map[string]any) { m["client_secret"] = strings.Repeat("x", 600) },
	} {
		bad := entraForm(e)
		mod(bad)
		var er map[string]string
		if got := e.call(root, "PUT", "/api/v1/integrations/entra", bad, &er, nil); got != 400 || er["error"] == "" {
			t.Errorf("%s = %d %v", name, got, er)
		}
	}
	var one struct {
		Configured bool `json:"configured"`
	}
	if e.call(root, "GET", "/api/v1/integrations/entra", nil, &one, nil); one.Configured {
		t.Fatal("a refused save changed the settings")
	}

	// Saved: the secret never comes back.
	if got := e.call(root, "PUT", "/api/v1/integrations/entra", entraForm(e), &v, nil); got != 200 || v["configured"] != true || v["enabled"] != true || v["has_secret"] != true {
		t.Fatalf("save = %d %v", got, v)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), entratest.ClientSecret) || strings.Contains(string(raw), "client_secret") {
		t.Errorf("the secret came back: %s", raw)
	}
	if v["redirect_uri"] != "https://siem.example.com:8443/api/v1/auth/entra/callback" {
		t.Errorf("redirect_uri = %v", v["redirect_uri"])
	}
	var list struct {
		Integrations []struct{ ID, State string }
	}
	e.call(root, "GET", "/api/v1/integrations", nil, &list, nil)
	states := map[string]string{}
	for _, i := range list.Integrations {
		states[i.ID] = i.State
	}
	if states["entra"] != "on" || states["email"] != "needs_setup" {
		t.Errorf("cards = %v", states)
	}

	// The connection test says what it found, and explains failures.
	var res map[string]any
	if got := e.call(root, "POST", "/api/v1/integrations/entra/test", map[string]any{"tenant_id": entratest.Tenant, "client_id": entratest.ClientID,
		"public_url": "https://siem.example.com:8443", "access_group_id": entratest.AccessGroup}, &res, nil); got != 200 || res["access_group_members"] != float64(2) {
		t.Errorf("test = %d %v", got, res)
	}
	wrong := entraForm(e)
	wrong["client_secret"] = "not-the-secret"
	var er map[string]string
	if got := e.call(root, "POST", "/api/v1/integrations/entra/test", wrong, &er, nil); got != 502 || !strings.Contains(er["error"], "client secret") {
		t.Errorf("wrong secret = %d %v", got, er)
	}
	// The saved secret isn't tried against a different app.
	other := map[string]any{"tenant_id": entratest.Tenant, "client_id": "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee",
		"public_url": "https://siem.example.com:8443", "access_group_id": entratest.AccessGroup}
	if got := e.call(root, "POST", "/api/v1/integrations/entra/test", other, &er, nil); got != 400 || !strings.Contains(er["error"], "enter its client secret") {
		t.Errorf("another app = %d %v", got, er)
	}
	if got := e.call(root, "PUT", "/api/v1/integrations/entra", other, &er, nil); got != 400 || !strings.Contains(er["error"], "enter the client secret again") {
		t.Errorf("save for another app = %d %v", got, er)
	}

	// Sync now.
	var st map[string]any
	if got := e.call(root, "POST", "/api/v1/integrations/entra/sync", nil, &st, nil); got != 200 || st["ok"] != true || st["members"] != float64(2) {
		t.Errorf("sync = %d %v", got, st)
	}
	e.ms.GraphStatus = 403
	if got := e.call(root, "POST", "/api/v1/integrations/entra/sync", nil, &er, nil); got != 502 || !strings.Contains(er["error"], "GroupMember.Read.All") {
		t.Errorf("sync without permission = %d %v", got, er)
	}
	e.ms.GraphStatus = 0

	// Off, and the sign-in page stops offering it.
	var prov map[string]bool
	if got := e.call(e.client(), "GET", "/api/v1/auth/providers", nil, &prov, nil); got != 200 || !prov["entra"] {
		t.Errorf("providers on = %d %v", got, prov)
	}
	var card map[string]any
	if got := e.call(root, "POST", "/api/v1/integrations/entra/enabled", map[string]any{"enabled": false}, &card, nil); got != 200 || card["state"] != "off" {
		t.Errorf("turn off = %d %v", got, card)
	}
	if e.call(e.client(), "GET", "/api/v1/auth/providers", nil, &prov, nil); prov["entra"] {
		t.Error("providers still lists Microsoft while it is off")
	}
	if got := e.call(root, "POST", "/api/v1/integrations/entra/sync", nil, &er, nil); got != 400 {
		t.Errorf("sync while off = %d", got)
	}
	// Remove.
	if got := e.call(root, "PUT", "/api/v1/integrations/entra", map[string]any{}, &v, nil); got != 200 || v["configured"] != false {
		t.Errorf("remove = %d %v", got, v)
	}
}

func TestSignInWithMicrosoft(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	e.ms.Set(entratest.AccessGroup, annOID, true)
	e.ms.Set(entratest.AccessGroup, caraOID, true)
	if got := e.call(root, "PUT", "/api/v1/integrations/entra", entraForm(e), nil, nil); got != 200 {
		t.Fatalf("save = %d", got)
	}

	// Start: a redirect to Microsoft with a short-lived, locked-down cookie.
	br := e.browser()
	resp := e.get(br, "/api/v1/auth/entra/start")
	fc := setCookie(resp, "siemlite_sso")
	if fc == nil || !fc.HttpOnly || !fc.Secure || fc.SameSite != http.SameSiteLaxMode || fc.Path != "/api/v1/auth/entra" || fc.MaxAge <= 0 || fc.MaxAge > 600 {
		t.Fatalf("flow cookie = %+v", fc)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("the start redirect can be cached")
	}
	authURL, state := e.startSSO(br)
	e.ms.Expect(authURL, annOID, "Ann@Example.com")

	// Back from Microsoft: signed in, the flow cookie gone, the session cookie strict.
	resp = e.get(br, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state="+state)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("the callback redirect leaks or caches")
	}
	sess := setCookie(resp, auth.CookieName)
	if sess == nil || sess.Value == "" || !sess.HttpOnly || !sess.Secure || sess.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v", sess)
	}
	if cleared := setCookie(resp, "siemlite_sso"); cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("the flow cookie wasn't cleared: %+v", cleared)
	}
	var me struct{ Username, Role string }
	if got := e.call(br, "GET", "/api/v1/me", nil, &me, nil); got != 200 || me.Username != "ann@example.com" || me.Role != "standard" {
		t.Fatalf("me = %d %+v", got, me)
	}
	// A Standard user, so not the admin pages.
	if got := e.call(br, "GET", "/api/v1/integrations/entra", nil, nil, nil); got != 403 {
		t.Errorf("an SSO standard user reached admin = %d", got)
	}
	// The account shows how it signs in, and has no password to guess or reset.
	var users []struct {
		Username     string `json:"username"`
		AuthProvider string `json:"auth_provider"`
		Disabled     bool   `json:"disabled"`
		ID           int64  `json:"id"`
	}
	e.call(root, "GET", "/api/v1/users", nil, &users, nil)
	var annID int64
	for _, u := range users {
		if u.Username == "ann@example.com" && u.AuthProvider == "entra" && !u.Disabled {
			annID = u.ID
		}
	}
	if annID == 0 {
		t.Fatalf("users = %+v", users)
	}
	var er map[string]string
	if got := e.call(root, "POST", "/api/v1/users/"+strconv.FormatInt(annID, 10)+"/password", map[string]any{"password": "a-long-enough-password"}, &er, nil); got != 400 || !strings.Contains(er["error"], "another service") {
		t.Errorf("password for an SSO user = %d %v", got, er)
	}
	if got := e.login(e.client(), "ann@example.com", "anything-at-all-123"); got.StatusCode != 401 {
		t.Errorf("password sign-in for an SSO user = %d", got.StatusCode)
	}

	// Audit: a sign-in event with no secrets in it.
	deadline := time.Now().Add(3 * time.Second)
	var found bool
	for !found && time.Now().Before(deadline) {
		var ev struct {
			Events []struct{ Message string }
		}
		e.call(root, "GET", "/api/v1/search?q=Microsoft&limit=20", nil, &ev, nil)
		for _, x := range ev.Events {
			found = found || strings.Contains(x.Message, "ann@example.com signed in with Microsoft")
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !found {
		t.Error("no audit event for the sign-in")
	}

	// Removal: the next membership check switches her off and ends the session.
	e.ms.Remove(entratest.AccessGroup, annOID)
	var st map[string]any
	if got := e.call(root, "POST", "/api/v1/integrations/entra/sync", nil, &st, nil); got != 200 || st["disabled"] != float64(1) {
		t.Fatalf("sync = %d %v", got, st)
	}
	if got := e.call(br, "GET", "/api/v1/me", nil, nil, nil); got != 401 {
		t.Errorf("a removed person's session still works = %d", got)
	}
	// And she can't get back in until she is in the group again.
	br2 := e.browser()
	authURL, state = e.startSSO(br2)
	e.ms.Expect(authURL, annOID, "ann@example.com")
	resp = e.get(br2, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state="+state)
	if resp.Header.Get("Location") != "/?sso_error=not_in_group" || setCookie(resp, auth.CookieName) != nil {
		t.Errorf("a removed person signed in: %d %q cookie=%v", resp.StatusCode, resp.Header.Get("Location"), setCookie(resp, auth.CookieName))
	}
}

func TestSignInWithMicrosoftRefusals(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)

	// Not set up: the start goes back to the sign-in page, and the page offers no button.
	br := e.browser()
	if resp := e.get(br, "/api/v1/auth/entra/start"); resp.Header.Get("Location") != "/?sso_error=off" {
		t.Errorf("start while off = %q", resp.Header.Get("Location"))
	}
	e.call(root, "PUT", "/api/v1/integrations/entra", entraForm(e), nil, nil)
	e.ms.Set(entratest.AccessGroup, annOID, true)

	for name, tc := range map[string]struct {
		query string
		prep  func(c *http.Client)
		want  string
	}{
		"no flow cookie": {"code=" + entratest.Code + "&state=x", func(c *http.Client) {}, "expired"},
		"cancelled":      {"error=access_denied&error_description=hidden", func(c *http.Client) {}, "denied"},
		"no parameters":  {"", func(c *http.Client) {}, "expired"},
	} {
		c := e.browser()
		tc.prep(c)
		resp := e.get(c, "/api/v1/auth/entra/callback?"+tc.query)
		if resp.Header.Get("Location") != "/?sso_error="+tc.want || setCookie(resp, auth.CookieName) != nil {
			t.Errorf("%s: %q session=%v", name, resp.Header.Get("Location"), setCookie(resp, auth.CookieName))
		}
	}

	// A wrong state with a real flow cookie.
	c := e.browser()
	authURL, _ := e.startSSO(c)
	e.ms.Expect(authURL, annOID, "ann@example.com")
	resp := e.get(c, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state=not-the-state")
	if resp.Header.Get("Location") != "/?sso_error=failed" || setCookie(resp, auth.CookieName) != nil {
		t.Errorf("wrong state: %q", resp.Header.Get("Location"))
	}
	// The cookie is spent: the genuine state no longer works for this browser.
	u, _ := url.Parse(authURL)
	state := u.Query().Get("state")
	resp = e.get(c, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state="+state)
	if resp.Header.Get("Location") != "/?sso_error=expired" {
		t.Errorf("reusing a spent flow: %q", resp.Header.Get("Location"))
	}
	// A forged token never signs anyone in.
	c = e.browser()
	authURL, state = e.startSSO(c)
	e.ms.Opts.OtherKey = entratest.RSAKey(t)
	e.ms.Expect(authURL, annOID, "ann@example.com")
	resp = e.get(c, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state="+state)
	if resp.Header.Get("Location") != "/?sso_error=failed" || setCookie(resp, auth.CookieName) != nil {
		t.Errorf("forged token: %q", resp.Header.Get("Location"))
	}
	e.ms.Opts = entratest.TokenOptions{}

	// A name already used by a local account is refused, and not taken over.
	e.user("ann@example.com", auth.RoleAdmin)
	c = e.browser()
	authURL, state = e.startSSO(c)
	e.ms.Expect(authURL, annOID, "ann@example.com")
	resp = e.get(c, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state="+state)
	if resp.Header.Get("Location") != "/?sso_error=name_taken" || setCookie(resp, auth.CookieName) != nil {
		t.Errorf("name taken: %q", resp.Header.Get("Location"))
	}

	// Repeated failures lock the address out of sign-in, like wrong passwords do.
	for i := 0; i < 12; i++ {
		e.get(e.browser(), "/api/v1/auth/entra/callback?code=x&state=y")
	}
	if resp := e.get(e.browser(), "/api/v1/auth/entra/callback?code=x&state=y"); resp.Header.Get("Location") != "/?sso_error=too_many" {
		t.Errorf("after many failures: %q", resp.Header.Get("Location"))
	}
}

func TestTurningOffEntraCannotLockEveryoneOut(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin) // a local admin, to configure it
	root := e.client()
	e.login(root, "root", password)
	form := entraForm(e)
	form["admin_group_id"] = entratest.AdminGroup
	if got := e.call(root, "PUT", "/api/v1/integrations/entra", form, nil, nil); got != 200 {
		t.Fatalf("save = %d", got)
	}
	e.ms.Set(entratest.AccessGroup, annOID, true)
	e.ms.Set(entratest.AdminGroup, annOID, true)
	br := e.browser()
	authURL, state := e.startSSO(br)
	e.ms.Expect(authURL, annOID, "ann@example.com")
	if resp := e.get(br, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state="+state); resp.Header.Get("Location") != "/" {
		t.Fatalf("sign-in = %q", resp.Header.Get("Location"))
	}
	var me struct{ Role string }
	if got := e.call(br, "GET", "/api/v1/me", nil, &me, nil); got != 200 || me.Role != "admin" {
		t.Fatalf("ann = %d %+v", got, me)
	}

	// The local admin can turn it off: Ann's session ends, and she can't sign in again until it is back on.
	var card map[string]any
	if got := e.call(root, "POST", "/api/v1/integrations/entra/enabled", map[string]any{"enabled": false}, &card, nil); got != 200 || card["state"] != "off" {
		t.Fatalf("turn off = %d %v", got, card)
	}
	if got := e.call(br, "GET", "/api/v1/me", nil, nil, nil); got != 401 {
		t.Errorf("a Microsoft session survived turning it off = %d", got)
	}
	if got := e.call(root, "GET", "/api/v1/me", nil, nil, nil); got != 200 {
		t.Errorf("the local admin was signed out = %d", got)
	}
	e.call(root, "POST", "/api/v1/integrations/entra/enabled", map[string]any{"enabled": true}, nil, nil)

	// Without any local admin left, the same request is refused.
	if err := e.repo.SetUserDisabled(t.Context(), 1, true); err != nil && !strings.Contains(err.Error(), "admin") {
		t.Fatal(err)
	}
	ann := e.browser()
	authURL, state = e.startSSO(ann)
	e.ms.Expect(authURL, annOID, "ann@example.com")
	e.get(ann, "/api/v1/auth/entra/callback?code="+entratest.Code+"&state="+state)
	var er map[string]string
	if got := e.call(ann, "POST", "/api/v1/integrations/entra/enabled", map[string]any{"enabled": false}, &er, nil); got != 400 || !strings.Contains(er["error"], "lock everyone out") {
		t.Errorf("turning off as the only admin = %d %v", got, er)
	}
	if got := e.call(ann, "PUT", "/api/v1/integrations/entra", map[string]any{}, &er, nil); got != 400 {
		t.Errorf("removing as the only admin = %d %v", got, er)
	}
	if got := e.call(ann, "GET", "/api/v1/me", nil, nil, nil); got != 200 {
		t.Errorf("the refused change signed her out = %d", got)
	}
}
