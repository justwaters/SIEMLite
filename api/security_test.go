package api_test

// The security regression suite. Each check guards one finding of the
// security audit (see SECURITY-AUDIT.md) so a later change can't quietly undo
// its fix. Add a check by appending to securityChecks; run them all with
// scripts/security-check.sh, or one with:
//
//	go test ./api -run 'TestSecurity/<name>'

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"siemlite/api"
)

type securityCheck struct {
	name string
	run  func(t *testing.T)
}

var securityChecks = []securityCheck{
	{"headers-on-every-answer", checkSecurityHeaders},
	{"csp-hashes-every-inline-script", checkCSPHashes},
	{"api-answers-are-not-cached", checkAPINotCached},
	{"hsts-on-https", checkHSTS},
	{"no-directory-listing", checkNoDirectoryListing},
	{"cross-site-requests-refused", checkCrossSiteRefused},
	{"account-lockout-across-addresses", checkAccountLockout},
}

func TestSecurity(t *testing.T) {
	for _, c := range securityChecks {
		t.Run(c.name, c.run)
	}
}

// --- Finding: missing browser security headers ---

func checkSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/", "/api/v1/me", "/health", "/nonexistent"} {
		resp := e.do(e.client(), "GET", path, "", nil)
		want := map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		}
		for k, v := range want {
			if got := resp.Header.Get(k); got != v {
				t.Errorf("GET %s: %s = %q, want %q", path, k, got, v)
			}
		}
		csp := resp.Header.Get("Content-Security-Policy")
		for _, directive := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, directive) {
				t.Errorf("GET %s: Content-Security-Policy lacks %q: %q", path, directive, csp)
			}
		}
		if strings.Contains(scriptSrc(csp), "unsafe-inline") || strings.Contains(scriptSrc(csp), "unsafe-eval") {
			t.Errorf("GET %s: script-src allows inline or eval: %q", path, csp)
		}
	}
}

func scriptSrc(csp string) string {
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "script-src ") {
			return d
		}
	}
	return ""
}

// The page's inline scripts must each be allowed by hash, and nothing else.
func checkCSPHashes(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.srv.URL+"/", nil)
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	src := scriptSrc(resp.Header.Get("Content-Security-Policy"))
	scripts := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllSubmatch(page, -1)
	if len(scripts) == 0 {
		t.Fatal("the page has no inline scripts; the check needs updating")
	}
	for i, m := range scripts {
		sum := sha256.Sum256(m[1])
		h := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !strings.Contains(src, h) {
			t.Errorf("inline script %d isn't allowed by the policy: %s", i, src)
		}
	}
	if n := strings.Count(src, "'sha256-"); n != len(scripts) {
		t.Errorf("policy allows %d script hashes, the page has %d inline scripts", n, len(scripts))
	}
}

// --- Finding: API answers cacheable by the browser ---

func checkAPINotCached(t *testing.T) {
	e := newEnv(t)
	e.user("admin", "admin")
	c := e.client()
	expect(t, "login", e.login(c, "admin", password), http.StatusOK)
	for _, path := range []string{"/api/v1/me", "/api/v1/users", "/api/v1/search"} {
		resp := e.do(c, "GET", path, "", nil)
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s: Cache-Control = %q, want no-store", path, got)
		}
	}
	if got := e.do(c, "GET", "/", "", nil).Header.Get("Cache-Control"); got == "no-store" {
		t.Error("the page itself may be cached; only API answers must not be")
	}
}

// --- Finding: no HSTS on the HTTPS listener ---

func checkHSTS(t *testing.T) {
	e := newEnv(t) // an httptest TLS server
	resp := e.do(e.client(), "GET", "/", "", nil)
	if got := resp.Header.Get("Strict-Transport-Security"); !strings.HasPrefix(got, "max-age=") {
		t.Errorf("Strict-Transport-Security = %q over HTTPS", got)
	}
}

// --- Finding: embedded folders could be listed ---

func checkNoDirectoryListing(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	expect(t, "GET /fonts/", e.do(c, "GET", "/fonts/", "", nil), http.StatusNotFound)
	expect(t, "GET /fonts", e.do(c, "GET", "/fonts", "", nil), http.StatusNotFound)
	expect(t, "GET /fonts/instrument-sans.woff2", e.do(c, "GET", "/fonts/instrument-sans.woff2", "", nil), http.StatusOK)
	expect(t, "GET /", e.do(c, "GET", "/", "", nil), http.StatusOK)
}

// --- Finding: cross-site requests only refused by Origin ---

func checkCrossSiteRefused(t *testing.T) {
	e := newEnv(t)
	e.user("admin", "admin")
	c := e.client()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})

	// Sign-in: a browser elsewhere says so with Sec-Fetch-Site even when it
	// sends no Origin.
	expect(t, "login from another site (Origin)", e.do(c, "POST", "/api/v1/login", string(body),
		map[string]string{"Origin": "https://evil.example"}), http.StatusForbidden)
	expect(t, "login from another site (Sec-Fetch-Site)", e.do(c, "POST", "/api/v1/login", string(body),
		map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusForbidden)
	expect(t, "login from a sibling site", e.do(c, "POST", "/api/v1/login", string(body),
		map[string]string{"Sec-Fetch-Site": "same-site"}), http.StatusForbidden)
	expect(t, "login from this site", e.do(c, "POST", "/api/v1/login", string(body),
		map[string]string{"Sec-Fetch-Site": "same-origin"}), http.StatusOK)

	// State changes with the session cookie.
	expect(t, "cross-site POST with cookie", e.do(c, "POST", "/api/v1/backups", "",
		map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusForbidden)
	expect(t, "cross-site logout", e.do(c, "POST", "/api/v1/logout", "",
		map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusForbidden)
	expect(t, "same-origin GET still works", e.do(c, "GET", "/api/v1/users", "",
		map[string]string{"Sec-Fetch-Site": "same-origin"}), http.StatusOK)
	// A navigation (typing the address) is "none" and a tool sends nothing.
	expect(t, "GET with no fetch metadata", e.do(c, "GET", "/api/v1/users", "", nil), http.StatusOK)
	expect(t, "same-origin logout", e.do(c, "POST", "/api/v1/logout", "",
		map[string]string{"Sec-Fetch-Site": "same-origin"}), http.StatusOK)
}

// --- Finding: sign-in failures only counted per address ---

func checkAccountLockout(t *testing.T) {
	e := newEnvWith(t, func(d *api.Deps) {
		d.Proxies, _ = api.ParseProxies("127.0.0.1") // so each try can claim another address
	})
	e.user("alice", "standard")
	e.user("bob", "standard")
	c := e.client()
	for i := 0; i < 50; i++ {
		b, _ := json.Marshal(map[string]string{"username": "Alice", "password": "wrong-password-" + fmt.Sprint(i)})
		resp := e.do(c, "POST", "/api/v1/login", string(b), map[string]string{"X-Forwarded-For": fmt.Sprintf("203.0.113.%d", i+1)})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("try %d from a fresh address: status %d, want 401", i, resp.StatusCode)
		}
	}
	b, _ := json.Marshal(map[string]string{"username": "alice", "password": password})
	// Locked out, alice answers exactly like a wrong password, so the limit can't be used to find accounts.
	expect(t, "alice with the right password after a spray", e.do(c, "POST", "/api/v1/login", string(b),
		map[string]string{"X-Forwarded-For": "198.51.100.1"}), http.StatusUnauthorized)
	b, _ = json.Marshal(map[string]string{"username": "bob", "password": password})
	expect(t, "bob is unaffected", e.do(c, "POST", "/api/v1/login", string(b),
		map[string]string{"X-Forwarded-For": "198.51.100.2"}), http.StatusOK)
}
