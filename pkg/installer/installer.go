// Package installer installs SIEMLite as a systemd service on Linux, updates
// that install, and removes it again: `sudo siemlite install`.
//
// What it manages:
//
//	/usr/local/bin/siemlite             the program, owned by root so the service can't replace it
//	/etc/siemlite/siemlite.env          settings (SIEMLITE_<FLAG>=value), seeded once and never overwritten
//	/etc/systemd/system/siemlite.service  the hardened unit, rewritten on update unless an admin edited it
//	/var/lib/siemlite                   the data folder, 0700, owned by the unprivileged siemlite user
//
// Everything touches the file system through Env.Root and runs programs only
// through Env.Exec and Env.ExecAs (fixed argument lists, never a shell), so
// the decisions can be tested without a systemd host. A run first works out
// the whole plan from what is on disk, so --dry-run prints exactly the steps a
// real run takes, and a refusal changes nothing.
package installer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"siemlite/pkg/update"
)

// Where things go.
const (
	User      = "siemlite"
	BinPath   = "/usr/local/bin/siemlite"
	DataDir   = "/var/lib/siemlite"
	ConfDir   = "/etc/siemlite"
	EnvPath   = "/etc/siemlite/siemlite.env"
	UnitPath  = "/etc/systemd/system/siemlite.service"
	UnitName  = "siemlite.service"
	dbPath    = DataDir + "/siemlite.db"
	adminName = "admin"
)

// Options are the installer's command-line choices.
type Options struct {
	DryRun         bool // print the steps, change nothing
	Uninstall      bool // remove the service and program; keep the data unless Purge
	Purge          bool // with Uninstall: also delete the data, settings and user
	NoSyslog       bool // a first install leaves the syslog listeners off
	AllowDowngrade bool // install over a newer version
}

// Env is what the installer looks at and runs. Tests replace the pieces.
type Env struct {
	Root    string // the file system's root; "/" outside tests
	GOOS    string
	Euid    int
	Self    string // the program being installed (os.Executable)
	Version string // its release, e.g. "v0.28"
	Out     io.Writer

	// Exec runs a program with a fixed argument list and returns its output.
	Exec func(ctx context.Context, name string, args ...string) (string, error)
	// ExecAs runs a program as an unprivileged user with stdin, in dir.
	ExecAs func(ctx context.Context, user, dir, stdin, name string, args ...string) (string, error)
	// Have reports whether a program is on the PATH.
	Have func(name string) bool
	// Chown gives path to the user and its group (nothing else changes owner).
	Chown func(path, user string) error
	// GenPassword makes the first admin's password.
	GenPassword func() (string, error)
	Sleep       func(time.Duration)
}

// NewEnv returns an Env for this machine, installing the program self at the given release.
func NewEnv(self, version string, out io.Writer, genPassword func() (string, error)) *Env {
	return &Env{Root: "/", GOOS: runtime.GOOS, Euid: os.Geteuid(), Self: self, Version: version, Out: out,
		Exec: run, ExecAs: runAs, Have: func(n string) bool { _, err := exec.LookPath(n); return err == nil },
		Chown: chownTo, GenPassword: genPassword, Sleep: time.Sleep}
}

func (e *Env) p(name string) string { return filepath.Join(e.Root, name) }

func (e *Env) exists(name string) bool {
	_, err := os.Lstat(e.p(name))
	return err == nil
}

func (e *Env) read(name string) (string, bool) {
	b, err := os.ReadFile(e.p(name))
	return string(b), err == nil
}

func (e *Env) printf(format string, a ...any) { fmt.Fprintf(e.Out, format, a...) }

// Refusal explains why nothing was done.
type Refusal struct{ Reason string }

func (r Refusal) Error() string { return r.Reason }

// preflight returns why this host can't be installed to, or nil.
func (e *Env) preflight(o Options) error {
	if e.GOOS != "linux" {
		return Refusal{"the installer sets up a systemd service, so it only works on Linux (this is " + e.GOOS + "); run SIEMLite directly or use Docker"}
	}
	if e.inContainer() {
		return Refusal{"this looks like a container; install SIEMLite on the host, or run the Docker image (see the README)"}
	}
	if !e.exists("/run/systemd/system") {
		return Refusal{"systemd isn't running on this host, so there is no service to install; run siemlite directly, or use Docker"}
	}
	if !e.Have("systemctl") {
		return Refusal{"systemctl isn't on the PATH, so the service can't be managed"}
	}
	if e.Euid != 0 && !o.DryRun {
		return Refusal{"the installer needs root: run it with sudo (add --dry-run to see what it would do without)"}
	}
	return nil
}

// inContainer reports whether this runs in a container (as pkg/secaudit decides it).
func (e *Env) inContainer() bool {
	if e.exists("/.dockerenv") || e.exists("/run/.containerenv") {
		return true
	}
	cg, ok := e.read("/proc/1/cgroup")
	if !ok {
		return false // not readable (no /proc): nothing to tell, so not a container
	}
	for _, w := range []string{"docker", "kubepods", "containerd", "libpod"} {
		if strings.Contains(cg, w) {
			return true
		}
	}
	return false
}

// step is one change, described in the imperative ("write /etc/..."), which a
// dry run prints and a real run does.
type step struct {
	desc string
	do   func(ctx context.Context) error
}

// result is what the run found and decided, for the summary.
type result struct {
	steps    []step
	notes    []string // what changed, what was kept, and why
	oldVer   string   // "" on a fresh install
	password string   // the new admin's, shown once
}

// Run installs, updates or (with Uninstall) removes SIEMLite, narrating on e.Out.
func (e *Env) Run(ctx context.Context, o Options) error {
	if o.Purge && !o.Uninstall {
		return Refusal{"--purge only goes with --uninstall"}
	}
	if err := e.preflight(o); err != nil {
		return err
	}
	var r *result
	var err error
	if o.Uninstall {
		r, err = e.planUninstall(o)
	} else {
		r, err = e.planInstall(ctx, o)
	}
	if err != nil {
		return err
	}
	if o.DryRun {
		e.printf("Dry run: nothing will be changed. A real run would:\n")
		for i, s := range r.steps {
			e.printf("  %d. %s\n", i+1, s.desc)
		}
		e.summary(r, o)
		return nil
	}
	for _, s := range r.steps {
		e.printf("  %s\n", s.desc)
		if err := s.do(ctx); err != nil {
			if r.password != "" {
				// The account exists, so its password mustn't be lost with the failure.
				e.printf("\nThe admin account was already created: username %s, password %s\n", adminName, r.password)
			}
			return fmt.Errorf("%s: %w (stopped here; run the installer again after fixing it)", s.desc, err)
		}
	}
	e.summary(r, o)
	return nil
}

func (e *Env) summary(r *result, o Options) {
	e.printf("\n")
	for _, n := range r.notes {
		e.printf("  %s\n", n)
	}
	if r.password != "" && !o.DryRun {
		e.printf("\nAn admin account was created (the password is shown once, store it safely):\n\n  username: %s\n  password: %s\n\n", adminName, r.password)
	}
}

// ---- install and update ----

func (e *Env) planInstall(ctx context.Context, o Options) (*result, error) {
	r := &result{}
	add := func(desc string, do func(ctx context.Context) error) { r.steps = append(r.steps, step{desc, do}) }
	note := func(f string, a ...any) { r.notes = append(r.notes, fmt.Sprintf(f, a...)) }

	// What is there now.
	binHere := e.exists(BinPath)
	unitHere := e.exists(UnitPath)
	envText, envHere := e.read(EnvPath)
	fresh := !binHere && !unitHere
	if binHere {
		r.oldVer = installedVersion(ctx, e)
	}
	if r.oldVer != "" && update.Newer(r.oldVer, e.Version) && !o.AllowDowngrade {
		return nil, Refusal{fmt.Sprintf("the installed version %s is newer than this one (%s); the database may have been upgraded in ways this version can't read. Add --allow-downgrade to go back anyway", r.oldVer, e.Version)}
	}
	if e.Self == "" {
		return nil, Refusal{"can't tell where this program is, so can't copy it"}
	}
	binSame := sameFile(e.p(BinPath), e.Self) || (binHere && sameContent(e.p(BinPath), e.Self))
	if e.userExists(User) && !e.localUser(User) {
		return nil, Refusal{"an account named " + User + " exists but not in /etc/passwd (it comes from a directory such as LDAP or SSSD); the installer won't run the service as an account it can't vouch for. Remove or rename it, or install by hand"}
	}
	if !e.userExists(User) && !e.Have("useradd") {
		return nil, Refusal{"useradd isn't on the PATH, so the " + User + " user can't be created"}
	}

	// 1. the unprivileged user
	if !e.userExists(User) {
		add("create the system user "+User+" (no login, no home)", func(ctx context.Context) error {
			_, err := e.Exec(ctx, "useradd", "--system", "--user-group", "--no-create-home",
				"--home-dir", DataDir, "--shell", "/usr/sbin/nologin", User)
			return err
		})
		note("user: created %s", User)
	}

	// 2. the data folder
	dataFresh := !e.exists(dbPath)
	mkdir := func(dir string, mode fs.FileMode, owner string) func(context.Context) error {
		return func(context.Context) error {
			if err := os.MkdirAll(e.p(dir), mode); err != nil {
				return err
			}
			if err := os.Chmod(e.p(dir), mode); err != nil {
				return err
			}
			if owner != "" {
				return e.Chown(e.p(dir), owner)
			}
			return nil
		}
	}
	add("make the data folder "+DataDir+" (0700, owned by "+User+")", mkdir(DataDir, 0o700, User))
	if e.exists(DataDir) {
		note("data: kept everything in %s", DataDir)
	} else {
		note("data: %s is new", DataDir)
	}

	// 3. settings: seeded once, never overwritten
	if !envHere {
		seed := seedEnv(!o.NoSyslog)
		envText = seed
		add("write the settings "+EnvPath+" (0600) from the defaults", func(context.Context) error {
			if err := os.MkdirAll(e.p(ConfDir), 0o755); err != nil {
				return err
			}
			return writeAtomic(e.p(EnvPath), strings.NewReader(seed), 0o600)
		})
		note("config: wrote %s from the defaults; edit it, then run: systemctl restart %s", EnvPath, UnitName)
	} else {
		note("config: kept %s as you have it (it is never overwritten)", EnvPath)
	}

	// 4. the program, replaced atomically
	binChanged := false
	switch {
	case binSame:
		note("program: %s is already this version (%s)", BinPath, e.Version)
	default:
		binChanged = true
		add("copy this program to "+BinPath+" (0755, replaced atomically)", func(context.Context) error {
			if err := os.MkdirAll(e.p(path.Dir(BinPath)), 0o755); err != nil {
				return err
			}
			f, err := os.Open(e.Self)
			if err != nil {
				return err
			}
			defer f.Close()
			return writeAtomic(e.p(BinPath), f, 0o755)
		})
		if binHere && r.oldVer == "" {
			note("program: replaced the one in %s (its version couldn't be read) with %s", BinPath, e.Version)
		} else if r.oldVer == "" {
			note("program: installed %s", e.Version)
		} else {
			note("program: %s -> %s", r.oldVer, e.Version)
		}
	}
	add("check the installed program runs", func(ctx context.Context) error {
		out, err := e.Exec(ctx, BinPath, "version")
		if err != nil {
			return fmt.Errorf("%s version: %w", BinPath, err)
		}
		note("installed program says: %s", strings.TrimSpace(out))
		return nil
	})

	// 5. the unit
	want := renderUnit(UnitOptions{BindLowPorts: needsLowPorts(envText)})
	existing, _ := e.read(UnitPath)
	unitChanged := false
	switch decideUnit(existing, unitHere, want) {
	case unitWrite:
		unitChanged = true
		add("write "+UnitPath+" (hardened; to change it use: systemctl edit "+UnitName+")", func(context.Context) error {
			if err := os.MkdirAll(e.p(path.Dir(UnitPath)), 0o755); err != nil {
				return err
			}
			return writeAtomic(e.p(UnitPath), strings.NewReader(want), 0o644)
		})
		if unitHere {
			note("unit: updated %s to this version's", UnitPath)
		} else {
			note("unit: wrote %s", UnitPath)
		}
	case unitKeep:
		note("unit: %s is already current", UnitPath)
	case unitEdited:
		proposal := UnitPath + ".new"
		add("keep your edited "+UnitPath+" and save this version's as "+proposal, func(context.Context) error {
			return writeAtomic(e.p(proposal), strings.NewReader(want), 0o644)
		})
		note("unit: you have edited %s, so it was left alone; this version's is in %s (compare them: diff %s %s). Settings changes belong in a drop-in: systemctl edit %s", UnitPath, proposal, UnitPath, proposal, UnitName)
	}

	// 6. the first admin, made here so the password shows on this terminal
	if dataFresh {
		add("create the first admin account, with a generated password shown below", func(ctx context.Context) error {
			pw, err := e.GenPassword()
			if err != nil {
				return err
			}
			// The password goes in on stdin, never in argv; the account is made
			// as the service's own user so the database is owned by it.
			if _, err := e.ExecAs(ctx, User, DataDir, pw+"\n", BinPath, "users", "create", "-db", dbPath, "-username", adminName, "-role", "admin"); err != nil {
				// Not fatal: SIEMLite makes its own first admin when it starts with no
				// users, but the person must know to look for it, so say it now too.
				msg := fmt.Sprintf("WARNING: couldn't create the first admin account (%v). SIEMLite creates one itself when it starts and prints its password in the log: journalctl -u %s", err, UnitName)
				e.printf("  %s\n", msg)
				note("%s", msg)
				return nil
			}
			r.password = pw
			return nil
		})
	}

	// 7. systemd
	add("systemctl daemon-reload", func(ctx context.Context) error { _, err := e.Exec(ctx, "systemctl", "daemon-reload"); return err })
	add("systemctl enable "+UnitName, func(ctx context.Context) error { _, err := e.Exec(ctx, "systemctl", "enable", UnitName); return err })
	verb := "start"
	if !fresh && (binChanged || unitChanged) {
		verb = "restart"
	}
	add("systemctl "+verb+" "+UnitName, func(ctx context.Context) error { _, err := e.Exec(ctx, "systemctl", verb, UnitName); return err })
	add("wait for the service to be running", func(ctx context.Context) error {
		for i := 0; i < 15; i++ {
			if out, _ := e.Exec(ctx, "systemctl", "is-active", UnitName); strings.TrimSpace(out) == "active" {
				return nil
			}
			e.Sleep(time.Second)
		}
		return fmt.Errorf("the service didn't stay up; see: journalctl -u %s -n 50", UnitName)
	})
	if fresh {
		note("SIEMLite %s is installed and running: https://<this server>:8443 (the certificate is self-signed)", e.Version)
	} else {
		note("SIEMLite is running %s (was %s)", e.Version, orUnknown(r.oldVer))
	}
	note("updates: the System page can't replace the root-owned program; to update, run the new program with: sudo ./siemlite install")
	return r, nil
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// installedVersion asks the installed program for its version ("SIEMLite v0.27").
func installedVersion(ctx context.Context, e *Env) string {
	out, err := e.Exec(ctx, BinPath, "version")
	if err != nil {
		return ""
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// ---- uninstall ----

func (e *Env) planUninstall(o Options) (*result, error) {
	r := &result{}
	add := func(desc string, do func(ctx context.Context) error) { r.steps = append(r.steps, step{desc, do}) }
	note := func(f string, a ...any) { r.notes = append(r.notes, fmt.Sprintf(f, a...)) }
	if !e.exists(BinPath) && !e.exists(UnitPath) {
		note("SIEMLite isn't installed as a service here; nothing to remove")
		if !o.Purge || (!e.exists(DataDir) && !e.exists(ConfDir)) {
			return r, nil
		}
	}
	remove := func(name string) func(context.Context) error {
		return func(context.Context) error {
			err := os.Remove(e.p(name))
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
	}
	if e.exists(UnitPath) {
		add("systemctl disable --now "+UnitName, func(ctx context.Context) error {
			_, err := e.Exec(ctx, "systemctl", "disable", "--now", UnitName)
			return err
		})
		add("remove "+UnitPath, remove(UnitPath))
		if e.exists(UnitPath + ".new") {
			add("remove "+UnitPath+".new", remove(UnitPath+".new"))
		}
		add("systemctl daemon-reload", func(ctx context.Context) error { _, err := e.Exec(ctx, "systemctl", "daemon-reload"); return err })
	}
	if e.exists(BinPath) {
		add("remove "+BinPath, remove(BinPath))
	}
	if o.Purge {
		add("delete the data folder "+DataDir, func(context.Context) error { return os.RemoveAll(e.p(DataDir)) })
		add("delete the settings "+ConfDir, func(context.Context) error { return os.RemoveAll(e.p(ConfDir)) })
		if e.localUser(User) {
			if !e.Have("userdel") {
				return nil, Refusal{"userdel isn't on the PATH, so the " + User + " user can't be deleted (leave out --purge to keep it)"}
			}
			add("delete the user "+User, func(ctx context.Context) error { _, err := e.Exec(ctx, "userdel", User); return err })
		}
		note("removed SIEMLite, its data, its settings and the %s user", User)
	} else {
		note("removed the service and program; kept the data in %s, the settings in %s and the %s user. To delete them too: siemlite install --uninstall --purge", DataDir, ConfDir, User)
	}
	return r, nil
}

// ---- the user ----

// userExists reports whether the account exists anywhere the system looks
// (so a directory user such as LDAP or SSSD counts), on the real root, and
// reads /etc/passwd under Root otherwise.
func (e *Env) userExists(name string) bool {
	if e.Root == "/" {
		_, err := user.Lookup(name)
		return err == nil
	}
	return e.localUser(name)
}

// localUser reports whether name is in this machine's own /etc/passwd. The
// installer only runs the service as an account it can vouch for: one from a
// directory could have any uid, groups or shell.
func (e *Env) localUser(name string) bool {
	text, ok := e.read("/etc/passwd")
	if !ok {
		return false
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), name+":") {
			return true
		}
	}
	return false
}

// ---- settings ----

// seedEnv is the settings file a first install gets.
func seedEnv(syslog bool) string {
	var b strings.Builder
	b.WriteString(`# SIEMLite settings, read by siemlite.service (systemd EnvironmentFile format).
# Any server flag can be set as SIEMLITE_<FLAG>, e.g. -syslog-allow is
# SIEMLITE_SYSLOG_ALLOW; see "Options" in the README. After editing, run:
#   sudo systemctl restart siemlite
# The installer never overwrites this file. A listener on a port below 1024
# is allowed when the installer next writes the unit (sudo ./siemlite install).

# HTTPS for the web UI. Use localhost:8443 to keep it to this server.
SIEMLITE_ADDR=0.0.0.0:8443

`)
	prefix := ""
	if !syslog {
		prefix = "# "
	}
	b.WriteString("# Syslog listeners (only networks in SIEMLITE_SYSLOG_ALLOW may send; the default\n# is loopback and private ranges).\n")
	b.WriteString(prefix + "SIEMLITE_SYSLOG_UDP=:514\n")
	b.WriteString(prefix + "SIEMLITE_SYSLOG_TCP=:514\n")
	b.WriteString(`#SIEMLITE_SYSLOG_ALLOW=10.0.0.0/8
#SIEMLITE_SYSLOG_TLS=:6514

# Names or IPs people use to reach this server, for the generated certificate
# (set before the first start; it is generated once).
#SIEMLITE_TLS_HOSTS=siem.example.com
`)
	return b.String()
}

// lowPortVars are the settings that give a listen address.
var lowPortVars = []string{"SIEMLITE_ADDR", "SIEMLITE_LOCAL_ADDR", "SIEMLITE_HTTP_ADDR", "SIEMLITE_SYSLOG_UDP", "SIEMLITE_SYSLOG_TCP", "SIEMLITE_SYSLOG_TLS"}

// needsLowPorts reports whether the settings listen on a port below 1024,
// which needs CAP_NET_BIND_SERVICE.
func needsLowPorts(envText string) bool {
	sc := bufio.NewScanner(strings.NewReader(envText))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		if !contains(lowPortVars, strings.TrimSpace(strings.TrimPrefix(k, "export "))) {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		// host:port, :port or [v6]:port; a bare IPv6 address has no port to read.
		_, ps, err := net.SplitHostPort(v)
		if err != nil {
			continue
		}
		if port, err := strconv.Atoi(ps); err == nil && port > 0 && port < 1024 {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- the unit ----

// UnitOptions vary the unit.
type UnitOptions struct {
	BindLowPorts bool // allow listening below port 1024 (syslog on 514)
}

const unitHeader = "# Written by `siemlite install`; its checksum is "

// renderUnit returns the unit file: a header line holding the checksum of the
// rest, so a later run can tell an edited file from one it wrote.
func renderUnit(o UnitOptions) string {
	caps := "CapabilityBoundingSet=\n"
	if o.BindLowPorts {
		caps = "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
	}
	body := `
[Unit]
Description=SIEMLite
Documentation=https://github.com/justwaters/SIEMLite
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=` + User + `
Group=` + User + `
WorkingDirectory=` + DataDir + `
EnvironmentFile=` + EnvPath + `
ExecStart=` + BinPath + ` -db ` + dbPath + `
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
UMask=0077

# Hardening: the service sees the file system read-only except its data folder.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=` + DataDir + `
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
` + caps + `
[Install]
WantedBy=multi-user.target
`
	return unitHeader + checksum(body) + "\n" + body
}

func checksum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type unitDecision int

const (
	unitWrite  unitDecision = iota // new, or ours and unedited: write the current one
	unitKeep                       // already identical
	unitEdited                     // an admin changed it: keep it, save ours beside it
)

// decideUnit says what to do with the unit file on disk, given the one this
// version would write.
func decideUnit(existing string, exists bool, want string) unitDecision {
	if !exists {
		return unitWrite
	}
	if existing == want {
		return unitKeep
	}
	if strings.TrimSpace(existing) == "" {
		return unitWrite // nothing of the admin's to keep
	}
	first, body, _ := strings.Cut(existing, "\n")
	if sum, ok := strings.CutPrefix(first, unitHeader); ok && sum == checksum(body) {
		return unitWrite // ours, untouched: safe to replace
	}
	return unitEdited
}

// ---- files ----

// writeAtomic writes src to a temp file beside dest and renames it into place,
// so a running program or a reader never sees half a file.
func writeAtomic(dest string, src io.Reader, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".siemlite-install-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // gone already once renamed
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return err
	}
	// Persist the rename itself, so a power cut can't bring the old file back.
	if d, err := os.Open(filepath.Dir(dest)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func sameFile(a, b string) bool {
	ia, err1 := os.Stat(a)
	ib, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ia, ib)
}

func sameContent(a, b string) bool {
	ha, err1 := fileSum(a)
	hb, err2 := fileSum(b)
	return err1 == nil && err2 == nil && bytes.Equal(ha, hb)
}

func fileSum(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// ---- running programs ----

// execTimeout bounds one command, including a systemctl start on a slow host.
const execTimeout = 3 * time.Minute

// run is the real Exec: a shell-free command with a minimal environment.
func run(ctx context.Context, name string, args ...string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}
