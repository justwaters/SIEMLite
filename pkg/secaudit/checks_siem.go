package secaudit

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Private ranges a syslog allowlist may cover without a warning.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// onlyLocal reports whether a listen address ("host:port") is reachable from
// this machine only.
func onlyLocal(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func siemChecks() []Check {
	return []Check{
		{ID: "siem.user", Category: CatSIEMLite, Title: "SIEMLite doesn't run as root", Severity: High, Run: checkNotRoot},
		{ID: "siem.perms", Category: CatSIEMLite, Title: "Database, keys and backups are private to SIEMLite", Severity: High,
			Run: checkPerms, Apply: applyPerms, ApplyLabel: "Tighten permissions"},
		{ID: "siem.backups", Category: CatSIEMLite, Title: "Backups are made and recent", Severity: Medium, Run: checkBackups},
		{ID: "siem.update", Category: CatSIEMLite, Title: "SIEMLite is up to date", Severity: Medium, Run: checkUpdate},
		{ID: "siem.docker", Category: CatSIEMLite, Title: "The container can't control Docker", Severity: Critical, Run: checkDockerSocket},
	}
}

func checkNotRoot(_ context.Context, e *Env) Outcome {
	if e.Euid != 0 {
		return Outcome{Status: Pass, Detail: "SIEMLite runs as an unprivileged user."}
	}
	return Outcome{Status: Fail, Detail: "SIEMLite is running as root, so a flaw in it would give an attacker the whole server.",
		Fix: "Run SIEMLite as its own unprivileged user (the Docker image already does). To listen on port 514 or 443 without root, " +
			"give the program the capability: setcap 'cap_net_bind_service=+ep' /path/to/siemlite, or map the port in front of it."}
}

// permTarget is a path and the most permissive mode it should have.
type permTarget struct {
	path string
	max  fs.FileMode // permission bits that may be set
}

func (e *Env) permTargets() []permTarget {
	var t []permTarget
	c := e.Cfg
	add := func(p string, max fs.FileMode) {
		if p != "" {
			t = append(t, permTarget{p, max})
		}
	}
	add(c.SecretKeyPath, 0o600)
	add(c.TLSKeyPath, 0o600)
	add(c.DBPath, 0o600)
	if c.DBPath != "" {
		add(filepath.Dir(c.DBPath), 0o700)
	}
	add(c.BackupDir, 0o700)
	add(c.ACMEDir, 0o700)
	return t
}

// permProblem describes a path that is more open than max, and whether other
// users (not just the group) can reach it. Symbolic links and missing paths
// are not problems.
func permProblem(t permTarget) (msg string, world, ok bool) {
	info, err := os.Lstat(t.path)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 {
		return "", false, false
	}
	mode := info.Mode().Perm()
	if mode&^t.max == 0 {
		return "", false, false
	}
	return fmt.Sprintf("%s is %04o, should be %04o or tighter", t.path, mode, t.max), mode&0o007 != 0, true
}

func checkPerms(_ context.Context, e *Env) Outcome {
	if e.GOOS == "windows" {
		return Outcome{Status: Skip, Detail: "File modes aren't checked on Windows."}
	}
	var problems []string
	world := false
	for _, t := range e.permTargets() {
		if msg, w, bad := permProblem(t); bad {
			problems = append(problems, msg)
			world = world || w
		}
	}
	switch {
	case len(problems) == 0:
		return Outcome{Status: Pass, Detail: "The database, its folder, the secret key, the TLS key and the backups folder aren't open to other users."}
	case world:
		return Outcome{Status: Fail, Detail: "Other users on this server can read SIEMLite's data: " + strings.Join(problems, "; ") + ".",
			Fix: "Use Tighten permissions, or run chmod yourself. The secret key unlocks stored credentials and the TLS key lets anyone impersonate this server."}
	}
	return Outcome{Status: Warn, Detail: "Members of the server's group can read SIEMLite's data: " + strings.Join(problems, "; ") + ".",
		Fix: "Use Tighten permissions, or run chmod yourself, unless the group is deliberate."}
}

// applyPerms tightens the paths checkPerms complains about. It never follows
// links and only touches the paths SIEMLite itself owns (the ones it was
// started with).
func applyPerms(_ context.Context, e *Env) (string, error) {
	n := 0
	for _, t := range e.permTargets() {
		if _, _, bad := permProblem(t); !bad {
			continue
		}
		info, err := os.Lstat(t.path)
		if err != nil {
			return "", err
		}
		if err := os.Chmod(t.path, info.Mode().Perm()&t.max); err != nil {
			return "", fmt.Errorf("couldn't change %s: %w", t.path, err)
		}
		n++
	}
	return fmt.Sprintf("Tightened the permissions of %d paths.", n), nil
}

func checkBackups(_ context.Context, e *Env) Outcome {
	c := e.Cfg
	if c.BackupDir == "" {
		return Outcome{Status: Skip, Detail: "Backups aren't available on this server."}
	}
	if c.BackupIntervalHours == 0 {
		return Outcome{Status: Warn, Detail: "Automatic backups are off, so a failed disk or a ransomware attack could lose every log.",
			Fix: "On the System page, under Automatic backups, choose Every day and Save schedule. Copy backups off this server too."}
	}
	if c.LastBackup.IsZero() {
		return Outcome{Status: Warn, Detail: "Automatic backups are on but none has been made yet.",
			Fix: "Choose Create backup now on the System page, and check that it succeeds."}
	}
	age := e.Now().Sub(c.LastBackup)
	if limit := max(2*time.Duration(c.BackupIntervalHours)*time.Hour, 48*time.Hour); age > limit {
		return Outcome{Status: Warn, Detail: fmt.Sprintf("The newest backup is %d days old, though backups are meant to run every %d hours.", int(age.Hours()/24), c.BackupIntervalHours),
			Fix: "Create a backup now on the System page and look in the server log for why the schedule isn't keeping up."}
	}
	return Outcome{Status: Pass, Detail: fmt.Sprintf("Backups run every %d hours and the newest is %s old.", c.BackupIntervalHours, age.Round(time.Minute))}
}

func checkUpdate(_ context.Context, e *Env) Outcome {
	c := e.Cfg
	switch {
	case !c.UpdateChecks:
		return Outcome{Status: Skip, Detail: "Update checks are turned off on this server, so it can't tell whether it is current."}
	case c.UpdateAvailable:
		return Outcome{Status: Warn, Detail: fmt.Sprintf("You're running %s and %s is available.", c.Version, c.LatestVersion),
			Fix: "On the System page, choose Update and restart (make a backup first)."}
	}
	return Outcome{Status: Pass, Detail: "You're running " + c.Version + ", the latest release."}
}

func checkDockerSocket(_ context.Context, e *Env) Outcome {
	if !e.inContainer() {
		return Outcome{Status: Pass, Detail: "SIEMLite isn't in a container."}
	}
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if e.exists(p) {
			return Outcome{Status: Fail, Detail: "The Docker socket (" + p + ") is mounted into this container. Anyone who gets into SIEMLite can start a privileged container and own the host.",
				Fix: "Remove the docker.sock volume from the compose file and recreate the container."}
		}
	}
	return Outcome{Status: Pass, Detail: "The Docker socket isn't mounted in this container."}
}
