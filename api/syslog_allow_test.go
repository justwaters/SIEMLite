package api_test

import (
	"testing"

	"siemlite/pkg/auth"
)

// The syslog allowlist is saved, validated and read back; an empty list returns to the default.
func TestSyslogAllowlistManage(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)

	type view struct {
		Allow     []string `json:"allow"`
		Default   bool     `json:"default"`
		Listening bool     `json:"listening"`
	}
	var v view
	if got := e.call(root, "GET", "/api/v1/syslog/allow", nil, &v, nil); got != 200 || !v.Default || len(v.Allow) == 0 {
		t.Fatalf("initial = %d %+v", got, v)
	}
	if got := e.call(root, "PUT", "/api/v1/syslog/allow", map[string]any{"allow": []string{"not-an-ip"}}, nil, nil); got != 400 {
		t.Errorf("a bad entry = %d, want 400", got)
	}
	if got := e.call(root, "PUT", "/api/v1/syslog/allow", map[string]any{"allow": []string{"203.0.113.7", "198.51.100.77/24, 2001:db8::1"}}, &v, nil); got != 200 {
		t.Fatalf("save = %d", got)
	}
	want := []string{"203.0.113.7/32", "198.51.100.0/24", "2001:db8::1/128"}
	if v.Default || len(v.Allow) != 3 || v.Allow[0] != want[0] || v.Allow[1] != want[1] || v.Allow[2] != want[2] {
		t.Errorf("saved = %+v, want %v", v, want)
	}
	e.call(root, "GET", "/api/v1/syslog/allow", nil, &v, nil)
	if v.Default || len(v.Allow) != 3 {
		t.Errorf("read back = %+v", v)
	}
	if got := e.call(root, "PUT", "/api/v1/syslog/allow", map[string]any{"allow": []string{}}, &v, nil); got != 200 || !v.Default {
		t.Errorf("clearing = %d %+v, want the default", got, v)
	}
}
