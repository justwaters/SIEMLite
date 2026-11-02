package secaudit

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeStore is an in-memory Store.
type fakeStore map[string]string

func (f fakeStore) Setting(_ context.Context, k, def string) (string, error) {
	if v, ok := f[k]; ok {
		return v, nil
	}
	return def, nil
}

func (f fakeStore) SetSetting(_ context.Context, k, v string) error { f[k] = v; return nil }

// hostEnv is a Linux host laid out under a temp directory.
func hostEnv(t *testing.T, files map[string]string) *Env {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Env{Root: root, GOOS: "linux", Euid: 1000, Now: time.Now,
		Exec: func(context.Context, string, ...string) (string, error) { return "", os.ErrNotExist }}
}

func outcome(t *testing.T, id string, e *Env) Outcome {
	t.Helper()
	c, ok := Find(id)
	if !ok {
		t.Fatalf("no check %s", id)
	}
	return c.Run(context.Background(), e)
}

func TestSSH(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  Status
	}{
		{"no sshd", map[string]string{}, Pass},
		{"hardened", map[string]string{"/etc/ssh/sshd_config": "PermitRootLogin no\nPasswordAuthentication no\n"}, Pass},
		{"password auth", map[string]string{"/etc/ssh/sshd_config": "PermitRootLogin no\n"}, Warn},
		{"root password", map[string]string{"/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication no\n"}, Fail},
		{"first value wins", map[string]string{"/etc/ssh/sshd_config": "PermitRootLogin no\nPasswordAuthentication no\nPermitRootLogin yes\n"}, Pass},
		{"match is ignored", map[string]string{"/etc/ssh/sshd_config": "PasswordAuthentication no\nMatch User bob\n  PasswordAuthentication yes\n"}, Pass},
		{"include", map[string]string{
			"/etc/ssh/sshd_config":           "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n",
			"/etc/ssh/sshd_config.d/10.conf": "PermitEmptyPasswords yes\n",
		}, Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := outcome(t, "host.ssh", hostEnv(t, tc.files)); got.Status != tc.want {
				t.Errorf("status = %s (%s), want %s", got.Status, got.Detail, tc.want)
			}
		})
	}
}

func TestHostChecksSkipOffLinuxAndInContainers(t *testing.T) {
	e := hostEnv(t, map[string]string{"/.dockerenv": ""})
	if got := outcome(t, "host.ssh", e); got.Status != Skip || !strings.Contains(got.Detail, "container") {
		t.Errorf("container = %s %q", got.Status, got.Detail)
	}
	e = hostEnv(t, nil)
	e.GOOS = "darwin"
	if got := outcome(t, "host.firewall", e); got.Status != Skip {
		t.Errorf("darwin = %s", got.Status)
	}
}

func TestAccounts(t *testing.T) {
	e := hostEnv(t, map[string]string{
		"/etc/passwd": "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n",
		"/etc/shadow": "root:!:1:::::\nalice::1:::::\n",
		"/etc/group":  "sudo:x:27:alice,bob,c,d,e,f\n",
	})
	if got := outcome(t, "host.uid0", e); got.Status != Fail || !strings.Contains(got.Detail, "toor") {
		t.Errorf("uid0 = %s %q", got.Status, got.Detail)
	}
	if got := outcome(t, "host.emptypw", e); got.Status != Fail || !strings.Contains(got.Detail, "alice") {
		t.Errorf("emptypw = %s %q", got.Status, got.Detail)
	}
	if got := outcome(t, "host.sudo", e); got.Status != Warn {
		t.Errorf("sudo with six admins = %s %q", got.Status, got.Detail)
	}
	e = hostEnv(t, map[string]string{"/etc/passwd": "root:x:0:0::/root:/bin/bash\n"})
	if got := outcome(t, "host.uid0", e); got.Status != Pass {
		t.Errorf("clean uid0 = %s", got.Status)
	}
	if got := outcome(t, "host.emptypw", e); got.Status != Skip {
		t.Errorf("unreadable shadow = %s, want skip", got.Status)
	}
}

func TestSystemFiles(t *testing.T) {
	e := hostEnv(t, map[string]string{"/etc/passwd": "root:x:0:0::/root:/bin/bash\n", "/etc/shadow": "root:!:1:::::\n"})
	if err := os.Chmod(e.path("/etc/shadow"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := outcome(t, "host.files", e); got.Status != Fail || !strings.Contains(got.Detail, "/etc/shadow") {
		t.Errorf("readable shadow = %s %q", got.Status, got.Detail)
	}
	if err := os.Chmod(e.path("/etc/shadow"), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := outcome(t, "host.files", e); got.Status != Pass {
		t.Errorf("fixed = %s %q", got.Status, got.Detail)
	}
}

func TestFirewall(t *testing.T) {
	e := hostEnv(t, nil)
	if got := outcome(t, "host.firewall", e); got.Status != Warn || !strings.Contains(got.Detail, "false alarm") {
		t.Errorf("none = %s %q", got.Status, got.Detail)
	}
	e = hostEnv(t, map[string]string{"/etc/ufw/ufw.conf": "# x\nENABLED=yes\n"})
	if got := outcome(t, "host.firewall", e); got.Status != Pass {
		t.Errorf("ufw = %s", got.Status)
	}
	e = hostEnv(t, nil)
	e.Exec = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && args[1] == "firewalld" {
			return "active\n", nil
		}
		return "inactive\n", os.ErrNotExist
	}
	if got := outcome(t, "host.firewall", e); got.Status != Pass {
		t.Errorf("firewalld = %s", got.Status)
	}
}

func TestKernel(t *testing.T) {
	e := hostEnv(t, map[string]string{"/proc/sys/kernel/randomize_va_space": "0\n", "/proc/sys/net/ipv4/tcp_syncookies": "1\n"})
	if got := outcome(t, "host.kernel", e); got.Status != Warn || !strings.Contains(got.Detail, "randomize_va_space") {
		t.Errorf("kernel = %s %q", got.Status, got.Detail)
	}
	e = hostEnv(t, map[string]string{"/proc/sys/kernel/randomize_va_space": "2\n"})
	if got := outcome(t, "host.kernel", e); got.Status != Pass {
		t.Errorf("kernel ok = %s", got.Status)
	}
}

func TestPorts(t *testing.T) {
	// 0.0.0.0:8443 (SIEMLite), 0.0.0.0:6379 (Redis), 127.0.0.1:5432, 0.0.0.0:9999, then a connected socket.
	tcp := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:20FB 00000000:0000 0A\n" +
		"   1: 00000000:18EB 00000000:0000 0A\n" +
		"   2: 0100007F:1538 00000000:0000 0A\n" +
		"   3: 00000000:270F 00000000:0000 0A\n" +
		"   4: 0100007F:C350 0100007F:20FB 01\n"
	e := hostEnv(t, map[string]string{"/proc/net/tcp": tcp})
	e.Cfg.Addr = "0.0.0.0:8443"
	got := outcome(t, "net.ports", e)
	if got.Status != Fail || !strings.Contains(got.Detail, "tcp/6379 (Redis)") || !strings.Contains(got.Detail, "tcp/9999") ||
		strings.Contains(got.Detail, "8443") || strings.Contains(got.Detail, "5432") {
		t.Errorf("ports = %s %q", got.Status, got.Detail)
	}
	if got := outcome(t, "net.ports", hostEnv(t, nil)); got.Status != Skip {
		t.Errorf("no /proc = %s", got.Status)
	}
	// IPv6 wildcard and loopback.
	v6 := "  sl  local_address rem_address st\n" +
		"   0: 00000000000000000000000000000000:2328 00000000000000000000000000000000:0000 0A\n" +
		"   1: 00000000000000000000000001000000:2329 00000000000000000000000000000000:0000 0A\n"
	e = hostEnv(t, map[string]string{"/proc/net/tcp6": v6})
	if got := outcome(t, "net.ports", e); got.Status != Warn || !strings.Contains(got.Detail, "tcp/9000") || strings.Contains(got.Detail, "9001") {
		t.Errorf("v6 ports = %s %q", got.Status, got.Detail)
	}
}

func TestSyslogAndHTTP(t *testing.T) {
	e := hostEnv(t, nil)
	if got := outcome(t, "net.syslog", e); got.Status != Pass {
		t.Errorf("syslog off = %s", got.Status)
	}
	e.Cfg.SyslogUDP = ":514"
	for allow, want := range map[string]Status{"": Pass, "10.0.0.0/8,192.168.1.5": Pass, "203.0.113.0/24": Warn, "0.0.0.0/0": Fail, "::/0": Fail} {
		e.Cfg.SyslogAllow = nil
		if allow != "" {
			e.Cfg.SyslogAllow = strings.Split(allow, ",")
		}
		if got := outcome(t, "net.syslog", e); got.Status != want {
			t.Errorf("syslog allow %q = %s (%s), want %s", allow, got.Status, got.Detail, want)
		}
	}
	for _, tc := range []struct {
		addr    string
		proxies bool
		want    Status
	}{{"", false, Pass}, {"127.0.0.1:8080", true, Pass}, {"0.0.0.0:8080", false, Fail}, {"127.0.0.1:8080", false, Warn}, {":8080", true, Warn}} {
		e.Cfg.HTTPAddr, e.Cfg.TrustedProxies = tc.addr, tc.proxies
		if got := outcome(t, "net.http", e); got.Status != tc.want {
			t.Errorf("http %q proxies=%v = %s, want %s", tc.addr, tc.proxies, got.Status, tc.want)
		}
	}
}

func TestCertBackupsUpdate(t *testing.T) {
	now := time.Now()
	e := hostEnv(t, nil)
	e.Cfg.Addr = "0.0.0.0:8443"
	for _, tc := range []struct {
		left       time.Duration
		selfSigned bool
		want       Status
	}{{-time.Hour, false, Fail}, {5 * 24 * time.Hour, false, Fail}, {20 * 24 * time.Hour, false, Warn},
		{90 * 24 * time.Hour, true, Warn}, {90 * 24 * time.Hour, false, Pass}} {
		e.Cfg.CertNotAfter, e.Cfg.CertSelfSigned = now.Add(tc.left), tc.selfSigned
		if got := outcome(t, "net.tls", e); got.Status != tc.want {
			t.Errorf("cert %v self-signed=%v = %s (%s), want %s", tc.left, tc.selfSigned, got.Status, got.Detail, tc.want)
		}
	}
	e.Cfg.Addr = "localhost:8443"
	e.Cfg.CertNotAfter, e.Cfg.CertSelfSigned = now.Add(90*24*time.Hour), true
	if got := outcome(t, "net.tls", e); got.Status != Pass {
		t.Errorf("self-signed on localhost = %s", got.Status)
	}

	e.Cfg.BackupDir = "/b"
	for _, tc := range []struct {
		hours int
		last  time.Duration // age of the newest backup; 0 = none
		want  Status
	}{{0, 0, Warn}, {24, 0, Warn}, {24, 72 * time.Hour, Warn}, {24, 3 * time.Hour, Pass}} {
		e.Cfg.BackupIntervalHours, e.Cfg.LastBackup = tc.hours, time.Time{}
		if tc.last > 0 {
			e.Cfg.LastBackup = now.Add(-tc.last)
		}
		if got := outcome(t, "siem.backups", e); got.Status != tc.want {
			t.Errorf("backups %dh last %v = %s, want %s", tc.hours, tc.last, got.Status, tc.want)
		}
	}

	e.Cfg = Config{Version: "v1"}
	if got := outcome(t, "siem.update", e); got.Status != Skip {
		t.Errorf("updates off = %s", got.Status)
	}
	e.Cfg = Config{Version: "v1", UpdateChecks: true, UpdateAvailable: true, LatestVersion: "v2"}
	if got := outcome(t, "siem.update", e); got.Status != Warn {
		t.Errorf("update available = %s", got.Status)
	}
}

func TestRootAndDockerSocket(t *testing.T) {
	e := hostEnv(t, map[string]string{"/.dockerenv": "", "/var/run/docker.sock": ""})
	if got := outcome(t, "siem.docker", e); got.Status != Fail {
		t.Errorf("socket = %s", got.Status)
	}
	if got := outcome(t, "siem.docker", hostEnv(t, nil)); got.Status != Pass {
		t.Errorf("no container = %s", got.Status)
	}
	e.Euid = 0
	if got := outcome(t, "siem.user", e); got.Status != Fail {
		t.Errorf("root = %s", got.Status)
	}
}

func TestPermsCheckAndApply(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "siemlite.key")
	if err := os.WriteFile(key, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := hostEnv(t, nil)
	e.Cfg.SecretKeyPath = key
	c, _ := Find("siem.perms")
	if got := c.Run(context.Background(), e); got.Status != Fail || !strings.Contains(got.Detail, key) {
		t.Fatalf("world-readable key = %s %q", got.Status, got.Detail)
	}
	if msg, err := c.Apply(context.Background(), e); err != nil || !strings.Contains(msg, "1 path") {
		t.Fatalf("apply = %q, %v", msg, err)
	}
	if info, _ := os.Stat(key); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o", info.Mode().Perm())
	}
	if got := c.Run(context.Background(), e); got.Status != Pass {
		t.Errorf("after fix = %s %q", got.Status, got.Detail)
	}
	// A symbolic link is never followed.
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	e.Cfg.SecretKeyPath = link
	if got := c.Run(context.Background(), e); got.Status != Pass {
		t.Errorf("symlink = %s", got.Status)
	}
}

func TestBrokenCheckBecomesSkip(t *testing.T) {
	res := RunCheck(context.Background(), hostEnv(t, nil), Check{ID: "x", Run: func(context.Context, *Env) Outcome { panic("boom") }})
	if res.Status != Skip || !strings.Contains(res.Detail, "boom") {
		t.Errorf("panic = %s %q", res.Status, res.Detail)
	}
}

func TestChecksAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Checks() {
		if c.ID == "" || c.Title == "" || c.Run == nil || c.Severity == "" || seen[c.ID] {
			t.Errorf("bad check %+v", c)
		}
		if c.Apply != nil && c.ApplyLabel == "" {
			t.Errorf("%s has a fix and no button text", c.ID)
		}
		seen[c.ID] = true
		if !slices.Contains(Categories, c.Category) {
			t.Errorf("%s has unknown category %q", c.ID, c.Category)
		}
	}
}

func TestServiceRepeatFixAndAccept(t *testing.T) {
	ctx := context.Background()
	store := fakeStore{}
	svc := New(store, "host1")
	dir := t.TempDir()
	key := filepath.Join(dir, "siemlite.key")
	if err := os.WriteFile(key, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := hostEnv(t, nil)
	e.Cfg = Config{Version: "v1", SecretKeyPath: key, Addr: "localhost:8443"}

	find := func(r *Run, id string) Result {
		for _, x := range r.Results {
			if x.ID == id {
				return x
			}
		}
		t.Fatalf("no result %s", id)
		return Result{}
	}
	if _, _, err := svc.Recheck(ctx, e, "siem.perms"); err != ErrNoRun {
		t.Fatalf("recheck before a run = %v", err)
	}
	first, err := svc.Run(ctx, e, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if p := find(first, "siem.perms"); p.Status != Fail || p.Change != "" {
		t.Fatalf("first run perms = %+v", p)
	}
	if first.Counts.Fail == 0 || first.Host != "host1" || first.By != "alice" {
		t.Errorf("first run = %+v", first.Counts)
	}

	// Accepting needs a reason and an open finding.
	if err := svc.Accept(ctx, "siem.perms", "alice", " "); err != ErrNoteEmpty {
		t.Errorf("empty note = %v", err)
	}
	if err := svc.Accept(ctx, "siem.docker", "alice", "x"); err != ErrNotOpen {
		t.Errorf("accept a pass = %v", err)
	}
	if err := svc.Accept(ctx, "nope", "alice", "x"); err != ErrUnknown {
		t.Errorf("accept unknown = %v", err)
	}
	if err := svc.Accept(ctx, "siem.perms", "alice", "single-user box"); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.State(ctx)
	if p := find(st.Last, "siem.perms"); p.Accepted == nil || p.Accepted.Note != "single-user box" {
		t.Errorf("accepted perms = %+v", p)
	}
	if st.Last.Counts.Accepted != 1 {
		t.Errorf("counts = %+v", st.Last.Counts)
	}
	if err := svc.Unaccept(ctx, "siem.perms"); err != nil {
		t.Fatal(err)
	}

	// Fix, and the recheck shows it resolved.
	msg, run, res, err := svc.Apply(ctx, e, "siem.perms")
	if err != nil || !strings.Contains(msg, "Tightened") {
		t.Fatalf("apply = %q %v", msg, err)
	}
	if res.Status != Pass || res.Change != "resolved" || find(run, "siem.perms").Status != Pass {
		t.Errorf("after apply = %+v", res)
	}
	if _, _, _, err := svc.Apply(ctx, e, "net.tls"); err != ErrNoFix {
		t.Errorf("apply without a fix = %v", err)
	}

	// A full re-run compares with the last: break it again and it is new.
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := svc.Run(ctx, e, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if p := find(second, "siem.perms"); p.Status != Fail || p.Change != "new" {
		t.Errorf("second run perms = %+v", p)
	}
	st, _ = svc.State(ctx)
	if len(st.History) != 2 || st.History[1].By != "bob" {
		t.Errorf("history = %+v", st.History)
	}
	md := second.Markdown()
	for _, want := range []string{"# SIEMLite security audit", "host1", "[FAIL] Database, keys and backups", "**To fix:**"} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

func TestAcceptanceLapsesWhenWorse(t *testing.T) {
	r := &Run{Results: []Result{{ID: "a", Status: Fail}, {ID: "b", Status: Warn}}}
	apply(r, map[string]Acceptance{"a": {Status: Warn}, "b": {Status: Fail}})
	if r.Results[0].Accepted != nil {
		t.Error("an acceptance of a warning must not cover a failure")
	}
	if r.Results[1].Accepted == nil {
		t.Error("an acceptance of a failure still covers a warning")
	}
}

func TestHistoryIsBounded(t *testing.T) {
	svc := New(fakeStore{}, "h")
	e := hostEnv(t, nil)
	e.GOOS = "plan9"
	for range historyKept + 5 {
		if _, err := svc.Run(context.Background(), e, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := svc.State(context.Background()); len(st.History) != historyKept {
		t.Errorf("history = %d", len(st.History))
	}
}

func TestSharedDirectoriesAreNeverManaged(t *testing.T) {
	for _, db := range []string{"/tmp/s.db", "/var/lib/s.db", "/s.db", filepath.Join(os.TempDir(), "s.db")} {
		if d := dataDir(db); d != "" {
			t.Errorf("dataDir(%s) = %q, want none", db, d)
		}
	}
	home, err := os.UserHomeDir()
	if err == nil {
		if d := dataDir(filepath.Join(home, "siemlite.db")); d != "" {
			t.Errorf("home directory managed: %s", d)
		}
	}
	own := t.TempDir()
	if d := dataDir(filepath.Join(own, "s.db")); d != own && d != "" {
		// The temporary folder may itself be a symlink on some systems; either way it is managed.
		t.Logf("dataDir resolved %s as %s", own, d)
	}
	if d := dataDir(filepath.Join(own, "s.db")); d == "" {
		t.Errorf("a private folder inside the temporary folder should be managed")
	}
}

func TestTightenRefusesASwappedLink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	target := filepath.Join(dir, "key")
	for _, p := range []string{victim, target} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A path that is a link isn't a problem and isn't touched.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := tighten(permTarget{link, 0o600}); err == nil {
		t.Error("tighten followed a symbolic link")
	}
	if info, _ := os.Stat(victim); info.Mode().Perm() != 0o644 {
		t.Errorf("the link's target was changed to %o", info.Mode().Perm())
	}
	if err := tighten(permTarget{target, 0o600}); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o", info.Mode().Perm())
	}
}

func TestCleanNote(t *testing.T) {
	if got := CleanNote("  why  "); got != "why" {
		t.Errorf("got %q", got)
	}
	if got := CleanNote(strings.Repeat("é", maxNote+50)); len([]rune(got)) != maxNote {
		t.Errorf("kept %d characters", len([]rune(got)))
	}
}

func TestPermsSkipsWhenNothingExists(t *testing.T) {
	e := hostEnv(t, nil)
	e.Cfg.SecretKeyPath = filepath.Join(t.TempDir(), "missing.key")
	if got := outcome(t, "siem.perms", e); got.Status != Skip {
		t.Errorf("nothing to examine = %s %q, want skip", got.Status, got.Detail)
	}
}

func TestAutoUpdatesTabIndented(t *testing.T) {
	e := hostEnv(t, map[string]string{"/etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade\t\"1\";\n"})
	if got := outcome(t, "host.updates", e); got.Status != Pass {
		t.Errorf("tab-indented = %s %q", got.Status, got.Detail)
	}
}
