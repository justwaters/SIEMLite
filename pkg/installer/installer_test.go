package installer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// host is a fake Linux/systemd machine under a temp dir.
type host struct {
	t       *testing.T
	root    string
	out     bytes.Buffer
	calls   []string // programs run as root, as "name arg arg"
	asCalls []string
	asStdin []string
	chowned []string
	active  string // what systemctl is-active says
	env     *Env
}

func newHost(t *testing.T, version string) *host {
	h := &host{t: t, root: t.TempDir(), active: "active"}
	h.write("/run/systemd/system/.keep", "")
	h.write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	h.env = &Env{Root: h.root, GOOS: "linux", Euid: 0, Version: version, Out: &h.out,
		Exec: func(_ context.Context, name string, args ...string) (string, error) {
			h.calls = append(h.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
			switch {
			case name == BinPath: // the installed program says its version: its file's content
				b, err := os.ReadFile(h.path(BinPath))
				return "SIEMLite " + string(b) + "\n", err
			case name == "useradd":
				h.append("/etc/passwd", User+":x:999:999::"+DataDir+":/usr/sbin/nologin\n")
			case name == "systemctl" && args[0] == "is-active":
				return h.active + "\n", nil
			}
			return "", nil
		},
		ExecAs: func(_ context.Context, user, dir, stdin, name string, args ...string) (string, error) {
			h.asCalls = append(h.asCalls, user+" "+dir+" "+name+" "+strings.Join(args, " "))
			h.asStdin = append(h.asStdin, stdin)
			h.write(dbPath, "") // the account creation makes the database
			return "", nil
		},
		Have: func(string) bool { return true },
		Chown: func(p, user string) error {
			h.chowned = append(h.chowned, user+" "+strings.TrimPrefix(p, h.root))
			return nil
		},
		GenPassword: func() (string, error) { return "s3cretPassw0rd", nil },
		Sleep:       func(time.Duration) {},
	}
	h.setBinary(version)
	return h
}

func (h *host) path(p string) string { return filepath.Join(h.root, p) }

func (h *host) write(p, text string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.path(p)), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.path(p), []byte(text), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) append(p, text string) {
	b, _ := os.ReadFile(h.path(p))
	h.write(p, string(b)+text)
}

func (h *host) read(p string) string {
	b, err := os.ReadFile(h.path(p))
	if err != nil {
		h.t.Fatalf("%s: %v", p, err)
	}
	return string(b)
}

func (h *host) has(p string) bool { _, err := os.Lstat(h.path(p)); return err == nil }

// setBinary makes the program being installed: its content is its version.
func (h *host) setBinary(version string) {
	self := filepath.Join(h.root, "download", "siemlite")
	if err := os.MkdirAll(filepath.Dir(self), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(self, []byte(version), 0o755); err != nil {
		h.t.Fatal(err)
	}
	h.env.Self, h.env.Version = self, version
}

func (h *host) run(o Options) error {
	h.calls, h.asCalls, h.asStdin, h.out = nil, nil, nil, bytes.Buffer{}
	return h.env.Run(context.Background(), o)
}

func (h *host) ran(call string) bool {
	for _, c := range h.calls {
		if c == call {
			return true
		}
	}
	return false
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestRefusesWithoutChangingAnything(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(h *host)
		want  string
	}{
		"not linux":    {func(h *host) { h.env.GOOS = "darwin" }, "only works on Linux"},
		"not root":     {func(h *host) { h.env.Euid = 1000 }, "needs root"},
		"docker":       {func(h *host) { h.write("/.dockerenv", "") }, "container"},
		"podman":       {func(h *host) { h.write("/run/.containerenv", "") }, "container"},
		"cgroup":       {func(h *host) { h.write("/proc/1/cgroup", "0::/kubepods/besteffort\n") }, "container"},
		"no systemd":   {func(h *host) { os.RemoveAll(h.path("/run/systemd")) }, "systemd isn't running"},
		"no systemctl": {func(h *host) { h.env.Have = func(n string) bool { return n != "systemctl" } }, "systemctl"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, "v0.28")
			tc.setup(h)
			err := h.run(Options{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if _, ok := err.(Refusal); !ok {
				t.Errorf("err is %T, want Refusal (main exits non-zero with a clean message)", err)
			}
			if len(h.calls) != 0 || len(h.asCalls) != 0 {
				t.Errorf("ran programs: %v %v", h.calls, h.asCalls)
			}
			for _, p := range []string{BinPath, UnitPath, EnvPath, DataDir} {
				if h.has(p) {
					t.Errorf("%s was created", p)
				}
			}
		})
	}
}

func TestDryRunChangesNothingEvenWithoutRoot(t *testing.T) {
	h := newHost(t, "v0.28")
	h.env.Euid = 1000
	if err := h.run(Options{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	out := h.out.String()
	for _, want := range []string{"Dry run", "create the system user siemlite", BinPath, EnvPath, UnitPath, "systemctl enable", "systemctl start"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "s3cretPassw0rd") {
		t.Error("a dry run printed a password")
	}
	for _, p := range []string{BinPath, UnitPath, EnvPath, DataDir} {
		if h.has(p) {
			t.Errorf("%s was created by a dry run", p)
		}
	}
	// Only read-only programs may run: the version of an installed program.
	if len(h.calls) != 0 || len(h.asCalls) != 0 {
		t.Errorf("a dry run ran %v %v", h.calls, h.asCalls)
	}
}

func TestFreshInstall(t *testing.T) {
	h := newHost(t, "v0.28")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	if got := h.read(BinPath); got != "v0.28" || mode(t, h.path(BinPath)) != 0o755 {
		t.Errorf("binary = %q mode %v", got, mode(t, h.path(BinPath)))
	}
	if mode(t, h.path(DataDir)) != 0o700 {
		t.Errorf("data dir mode = %v", mode(t, h.path(DataDir)))
	}
	if len(h.chowned) == 0 || h.chowned[0] != "siemlite "+DataDir {
		t.Errorf("chowned = %v", h.chowned)
	}
	if mode(t, h.path(EnvPath)) != 0o600 {
		t.Errorf("env mode = %v", mode(t, h.path(EnvPath)))
	}
	env := h.read(EnvPath)
	if !strings.Contains(env, "\nSIEMLITE_SYSLOG_UDP=:514\n") || !strings.Contains(env, "\nSIEMLITE_ADDR=0.0.0.0:8443\n") {
		t.Errorf("env defaults:\n%s", env)
	}
	unit := h.read(UnitPath)
	for _, want := range []string{"User=siemlite", "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true",
		"Restart=on-failure", "AmbientCapabilities=CAP_NET_BIND_SERVICE", "ReadWritePaths=/var/lib/siemlite",
		"EnvironmentFile=/etc/siemlite/siemlite.env", "ExecStart=/usr/local/bin/siemlite -db /var/lib/siemlite/siemlite.db"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	want := []string{"useradd --system --user-group --no-create-home --home-dir /var/lib/siemlite --shell /usr/sbin/nologin siemlite",
		"systemctl daemon-reload", "systemctl enable siemlite.service", "systemctl start siemlite.service"}
	for _, c := range want {
		if !h.ran(c) {
			t.Errorf("didn't run %q; ran %v", c, h.calls)
		}
	}
	// The admin password is shown on the terminal, goes in on stdin, and never in an argument.
	if !strings.Contains(h.out.String(), "password: s3cretPassw0rd") {
		t.Errorf("password not shown:\n%s", h.out.String())
	}
	if len(h.asCalls) != 1 || strings.Contains(h.asCalls[0], "s3cretPassw0rd") || h.asStdin[0] != "s3cretPassw0rd\n" ||
		!strings.HasPrefix(h.asCalls[0], "siemlite "+DataDir+" "+BinPath+" users create -db "+dbPath) {
		t.Errorf("admin creation: %v stdin %q", h.asCalls, h.asStdin)
	}
}

func TestNoSyslogLeavesPortsAndCapabilityOff(t *testing.T) {
	h := newHost(t, "v0.28")
	if err := h.run(Options{NoSyslog: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.read(EnvPath), "\nSIEMLITE_SYSLOG_UDP") || strings.Contains(h.read(UnitPath), "AmbientCapabilities") {
		t.Errorf("syslog or capability on:\n%s\n%s", h.read(EnvPath), h.read(UnitPath))
	}
	if !strings.Contains(h.read(UnitPath), "CapabilityBoundingSet=\n") {
		t.Error("the capability bounding set isn't emptied")
	}
}

func TestUpdateKeepsDataAndEditedConfig(t *testing.T) {
	h := newHost(t, "v0.27")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	h.write(EnvPath, "SIEMLITE_ADDR=localhost:9000\n# mine\n")
	h.write(DataDir+"/siemlite-events/day", "events")
	unitBefore := h.read(UnitPath)

	h.setBinary("v0.28")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	if h.read(BinPath) != "v0.28" {
		t.Errorf("binary = %q", h.read(BinPath))
	}
	if h.read(EnvPath) != "SIEMLITE_ADDR=localhost:9000\n# mine\n" {
		t.Errorf("the edited settings were changed:\n%s", h.read(EnvPath))
	}
	if h.read(DataDir+"/siemlite-events/day") != "events" || !h.has(dbPath) {
		t.Error("data lost")
	}
	if len(h.asCalls) != 0 || strings.Contains(h.out.String(), "password") {
		t.Errorf("an update made an admin account: %v", h.asCalls)
	}
	if !h.ran("systemctl restart siemlite.service") || h.ran("systemctl start siemlite.service") {
		t.Errorf("calls: %v", h.calls)
	}
	if h.ran("useradd --system --user-group --no-create-home --home-dir /var/lib/siemlite --shell /usr/sbin/nologin siemlite") {
		t.Error("created the user again")
	}
	out := h.out.String()
	for _, want := range []string{"program: v0.27 -> v0.28", "kept " + EnvPath, "kept everything in " + DataDir} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	// The low-port capability follows the settings: the edit moved everything above 1024.
	if unit := h.read(UnitPath); unit == unitBefore || strings.Contains(unit, "AmbientCapabilities") {
		t.Errorf("unit not re-rendered for the edited settings:\n%s", unit)
	}
}

func TestUpdateSameProgramDoesNotRestart(t *testing.T) {
	h := newHost(t, "v0.28")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	if h.ran("systemctl restart siemlite.service") || !h.ran("systemctl start siemlite.service") {
		t.Errorf("calls: %v", h.calls)
	}
	if !strings.Contains(h.out.String(), "already this version") {
		t.Errorf("output:\n%s", h.out.String())
	}
}

func TestEditedUnitIsKept(t *testing.T) {
	h := newHost(t, "v0.27")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	edited := h.read(UnitPath) + "Environment=FOO=bar\n"
	h.write(UnitPath, edited)
	h.setBinary("v0.28")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	if h.read(UnitPath) != edited {
		t.Error("the edited unit was overwritten")
	}
	if !strings.Contains(h.read(UnitPath+".new"), "ExecStart=") || !strings.Contains(h.out.String(), "you have edited") {
		t.Errorf("no proposal or note:\n%s", h.out.String())
	}
	if !h.ran("systemctl restart siemlite.service") {
		t.Error("the program changed but the service wasn't restarted")
	}
}

func TestDowngradeRefusedUnlessAllowed(t *testing.T) {
	h := newHost(t, "v0.28")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	h.setBinary("v0.27")
	err := h.run(Options{})
	if err == nil || !strings.Contains(err.Error(), "--allow-downgrade") {
		t.Fatalf("err = %v", err)
	}
	if h.read(BinPath) != "v0.28" || len(h.calls) != 1 { // only the version query
		t.Errorf("changed on refusal: %q %v", h.read(BinPath), h.calls)
	}
	if err := h.run(Options{AllowDowngrade: true}); err != nil || h.read(BinPath) != "v0.27" {
		t.Errorf("allowed downgrade: %v %q", err, h.read(BinPath))
	}
}

func TestInstallFromTheInstalledProgram(t *testing.T) {
	h := newHost(t, "v0.28")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	h.env.Self = h.path(BinPath)
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	if h.read(BinPath) != "v0.28" {
		t.Errorf("binary = %q", h.read(BinPath))
	}
}

func TestUninstallKeepsDataThenPurges(t *testing.T) {
	h := newHost(t, "v0.28")
	if err := h.run(Options{}); err != nil {
		t.Fatal(err)
	}
	if err := h.run(Options{Uninstall: true, DryRun: true}); err != nil || !h.has(BinPath) {
		t.Fatalf("dry run: %v", err)
	}
	if err := h.run(Options{Uninstall: true}); err != nil {
		t.Fatal(err)
	}
	if h.has(BinPath) || h.has(UnitPath) {
		t.Error("program or unit left")
	}
	if !h.has(dbPath) || !h.has(EnvPath) {
		t.Error("data or settings removed without --purge")
	}
	if !h.ran("systemctl disable --now siemlite.service") || h.ran("userdel siemlite") {
		t.Errorf("calls: %v", h.calls)
	}
	if err := h.run(Options{Uninstall: true, Purge: true}); err != nil {
		t.Fatal(err)
	}
	if h.has(DataDir) || h.has(ConfDir) || !h.ran("userdel siemlite") {
		t.Errorf("purge left data %v or conf %v; calls %v", h.has(DataDir), h.has(ConfDir), h.calls)
	}
	if err := h.run(Options{Purge: true}); err == nil {
		t.Error("--purge without --uninstall was accepted")
	}
}

func TestUninstallWhenNotInstalled(t *testing.T) {
	h := newHost(t, "v0.28")
	if err := h.run(Options{Uninstall: true}); err != nil {
		t.Fatal(err)
	}
	if len(h.calls) != 0 || !strings.Contains(h.out.String(), "isn't installed") {
		t.Errorf("calls %v\n%s", h.calls, h.out.String())
	}
}

func TestStartFailureIsReported(t *testing.T) {
	h := newHost(t, "v0.28")
	h.active = "failed"
	err := h.run(Options{})
	if err == nil || !strings.Contains(err.Error(), "journalctl -u siemlite") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(h.out.String(), "password s3cretPassw0rd") {
		t.Errorf("the admin password was lost with the failure:\n%s", h.out.String())
	}
}

func TestNeedsLowPorts(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want bool
	}{
		{"SIEMLITE_SYSLOG_UDP=:514\n", true},
		{"SIEMLITE_ADDR=0.0.0.0:443", true},
		{"SIEMLITE_SYSLOG_TCP=\"0.0.0.0:514\"", true},
		{"export SIEMLITE_SYSLOG_UDP=:514", true},
		{"#SIEMLITE_SYSLOG_UDP=:514\nSIEMLITE_ADDR=0.0.0.0:8443\n", false},
		{"SIEMLITE_SYSLOG_UDP=:5514\nSIEMLITE_SYSLOG_TLS=[::]:6514", false},
		{"SIEMLITE_SYSLOG_ALLOW=10.0.0.0/8:80", false}, // not a listen address
		{"SIEMLITE_ADDR=localhost", false},
		{"", false},
	} {
		if got := needsLowPorts(tc.env); got != tc.want {
			t.Errorf("needsLowPorts(%q) = %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestDecideUnit(t *testing.T) {
	want := renderUnit(UnitOptions{BindLowPorts: true})
	old := renderUnit(UnitOptions{})
	for name, tc := range map[string]struct {
		existing string
		exists   bool
		want     unitDecision
	}{
		"missing":          {"", false, unitWrite},
		"identical":        {want, true, unitKeep},
		"ours, older":      {old, true, unitWrite},
		"edited body":      {old + "Environment=X=1\n", true, unitEdited},
		"hand-written":     {"[Service]\nExecStart=/x\n", true, unitEdited},
		"edited checksum":  {strings.Replace(old, "NoNewPrivileges=true", "NoNewPrivileges=false", 1), true, unitEdited},
		"empty but exists": {"", true, unitWrite},
	} {
		if got := decideUnit(tc.existing, tc.exists, want); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestRenderUnitCapabilities(t *testing.T) {
	if u := renderUnit(UnitOptions{}); strings.Contains(u, "AmbientCapabilities") {
		t.Error("capability without low ports")
	}
	if u := renderUnit(UnitOptions{BindLowPorts: true}); !strings.Contains(u, "AmbientCapabilities=CAP_NET_BIND_SERVICE") {
		t.Error("no capability with low ports")
	}
}

func TestVersionOutput(t *testing.T) {
	h := newHost(t, "v0.28")
	h.setBinary("v0.28")
	h.write(BinPath, "v0.26")
	if got := installedVersion(context.Background(), h.env); got != "v0.26" {
		t.Errorf("installedVersion = %q", got)
	}
}
