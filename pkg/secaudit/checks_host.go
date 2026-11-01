package secaudit

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

func hostChecks() []Check {
	return []Check{
		{ID: "host.ssh", Category: CatHost, Title: "SSH is hardened", Severity: High, Run: checkSSH},
		{ID: "host.firewall", Category: CatHost, Title: "A firewall is active", Severity: High, Run: checkFirewall},
		{ID: "host.uid0", Category: CatHost, Title: "Only root has user ID 0", Severity: Critical, Run: checkUID0},
		{ID: "host.emptypw", Category: CatHost, Title: "No account has an empty password", Severity: Critical, Run: checkEmptyPasswords},
		{ID: "host.sudo", Category: CatHost, Title: "Administrator groups are small and need a password", Severity: Medium, Run: checkSudo},
		{ID: "host.files", Category: CatHost, Title: "System account files have safe permissions", Severity: High, Run: checkSystemFiles},
		{ID: "host.kernel", Category: CatHost, Title: "Kernel network and memory settings are safe", Severity: Medium, Run: checkKernel},
		{ID: "host.updates", Category: CatHost, Title: "Security updates install automatically", Severity: Low, Run: checkAutoUpdates},
	}
}

// sshdConfig returns the effective global settings of sshd_config, following
// Include. The first value of a keyword wins, as in sshd; Match blocks are
// conditional, so reading stops at the first one in each file.
func (e *Env) sshdConfig() (map[string]string, bool) {
	cfg := map[string]string{}
	found := false
	var load func(file string, depth int)
	load = func(file string, depth int) {
		text, err := e.read(file)
		if err != nil {
			return
		}
		found = true
		for _, line := range strings.Split(text, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			key := strings.ToLower(f[0])
			if key == "match" {
				return
			}
			if key == "include" && depth < 3 {
				for _, pat := range f[1:] {
					if !path.IsAbs(pat) {
						pat = "/etc/ssh/" + pat
					}
					matches, _ := filepath.Glob(e.path(pat))
					slices.Sort(matches)
					for _, m := range matches {
						rel, err := filepath.Rel(e.Root, m)
						if err == nil {
							load("/"+rel, depth+1)
						}
					}
				}
				continue
			}
			if _, set := cfg[key]; !set {
				cfg[key] = strings.ToLower(strings.Trim(strings.Join(f[1:], " "), `"`))
			}
		}
	}
	load("/etc/ssh/sshd_config", 0)
	return cfg, found
}

func checkSSH(_ context.Context, e *Env) Outcome {
	if o, skip := e.hostSkip(); skip {
		return o
	}
	cfg, found := e.sshdConfig()
	if !found {
		return Outcome{Status: Pass, Detail: "There's no SSH server configuration on this host."}
	}
	get := func(key, def string) string {
		if v, ok := cfg[key]; ok {
			return v
		}
		return def
	}
	var bad []string
	worst := Warn
	if v := get("permitrootlogin", "prohibit-password"); v == "yes" {
		bad, worst = append(bad, "root can sign in with a password (PermitRootLogin yes)"), Fail
	}
	if get("permitemptypasswords", "no") == "yes" {
		bad, worst = append(bad, "empty passwords are allowed (PermitEmptyPasswords yes)"), Fail
	}
	if get("passwordauthentication", "yes") == "yes" {
		bad = append(bad, "passwords are accepted, so SSH can be guessed at (PasswordAuthentication yes)")
	}
	if n, err := strconv.Atoi(get("maxauthtries", "6")); err == nil && n > 6 {
		bad = append(bad, fmt.Sprintf("%d password tries per connection are allowed (MaxAuthTries)", n))
	}
	if get("x11forwarding", "no") == "yes" {
		bad = append(bad, "X11 forwarding is on (X11Forwarding yes)")
	}
	if len(bad) == 0 {
		return Outcome{Status: Pass, Detail: "sshd refuses root passwords and empty passwords, and accepts keys only."}
	}
	return Outcome{Status: worst, Detail: "In sshd_config, " + strings.Join(bad, "; ") + ".",
		Fix: "Edit /etc/ssh/sshd_config (or a file in /etc/ssh/sshd_config.d/): set PermitRootLogin prohibit-password, PasswordAuthentication no, " +
			"PermitEmptyPasswords no, MaxAuthTries 4 and X11Forwarding no. Make sure your key works in a second session first, check with sshd -t, then reload sshd."}
}

func checkFirewall(ctx context.Context, e *Env) Outcome {
	if o, skip := e.hostSkip(); skip {
		return o
	}
	if conf, err := e.read("/etc/ufw/ufw.conf"); err == nil {
		for _, l := range strings.Split(conf, "\n") {
			if strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(l), " ", ""), "ENABLED=yes") {
				return Outcome{Status: Pass, Detail: "ufw is enabled."}
			}
		}
	}
	for _, unit := range []string{"firewalld", "nftables", "ufw"} {
		if out, _ := e.Exec(ctx, "systemctl", "is-active", unit); strings.TrimSpace(out) == "active" {
			return Outcome{Status: Pass, Detail: unit + " is active."}
		}
	}
	if e.Euid == 0 {
		if out, err := e.Exec(ctx, "iptables", "-S"); err == nil && strings.Contains(out, "-A ") {
			return Outcome{Status: Pass, Detail: "iptables has rules loaded."}
		}
		if out, err := e.Exec(ctx, "nft", "list", "ruleset"); err == nil && (strings.Contains(out, "rule") || strings.Contains(out, "policy drop")) {
			return Outcome{Status: Pass, Detail: "nftables has rules loaded."}
		}
	}
	d := "No active firewall was found (ufw, firewalld or nftables)."
	if e.Euid != 0 {
		d += " Rules loaded by hand with iptables can't be seen without root, so this may be a false alarm."
	}
	return Outcome{Status: Warn, Detail: d,
		Fix: "Turn one on and allow only what you use, for example: ufw default deny incoming, ufw allow 22/tcp, ufw allow 8443/tcp, ufw enable. " +
			"If a firewall in front of the server (a cloud security group) does this, use Accept risk and say so."}
}

type account struct {
	name     string
	uid, gid int
	shell    string
}

func (e *Env) accounts() ([]account, bool) {
	text, err := e.read("/etc/passwd")
	if err != nil {
		return nil, false
	}
	var out []account
	for _, l := range strings.Split(text, "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, account{name: f[0], uid: uid, gid: gid, shell: f[6]})
	}
	return out, true
}

func checkUID0(_ context.Context, e *Env) Outcome {
	if o, skip := e.hostSkip(); skip {
		return o
	}
	accts, ok := e.accounts()
	if !ok {
		return Outcome{Status: Skip, Detail: "/etc/passwd couldn't be read."}
	}
	var extra []string
	for _, a := range accts {
		if a.uid == 0 && a.name != "root" {
			extra = append(extra, a.name)
		}
	}
	if len(extra) > 0 {
		return Outcome{Status: Fail, Detail: "These accounts have user ID 0, which makes them root: " + strings.Join(extra, ", ") + ".",
			Fix: "Unless you created them on purpose, treat this as a possible intrusion. Remove or lock them (usermod -L name; userdel name) and look at the auth log for how they were made."}
	}
	return Outcome{Status: Pass, Detail: "root is the only account with user ID 0."}
}

func checkEmptyPasswords(_ context.Context, e *Env) Outcome {
	if o, skip := e.hostSkip(); skip {
		return o
	}
	text, err := e.read("/etc/shadow")
	if err != nil {
		return Outcome{Status: Skip, Detail: "/etc/shadow can only be read by root, and SIEMLite doesn't run as root. To check, run: awk -F: '($2 == \"\") {print $1}' /etc/shadow"}
	}
	var empty []string
	for _, l := range strings.Split(text, "\n") {
		if f := strings.Split(l, ":"); len(f) > 1 && f[0] != "" && f[1] == "" {
			empty = append(empty, f[0])
		}
	}
	if len(empty) > 0 {
		return Outcome{Status: Fail, Detail: "These accounts have no password: " + strings.Join(empty, ", ") + ".",
			Fix: "Lock each (passwd -l name) or set a password (passwd name)."}
	}
	return Outcome{Status: Pass, Detail: "No account has an empty password."}
}

func checkSudo(_ context.Context, e *Env) Outcome {
	if o, skip := e.hostSkip(); skip {
		return o
	}
	accts, ok := e.accounts()
	group, err := e.read("/etc/group")
	if !ok || err != nil {
		return Outcome{Status: Skip, Detail: "/etc/passwd or /etc/group couldn't be read."}
	}
	admins := map[string]bool{}
	for _, l := range strings.Split(group, "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 || !slices.Contains([]string{"sudo", "wheel", "admin"}, f[0]) {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if m != "" {
				admins[m] = true
			}
		}
		if gid, err := strconv.Atoi(f[2]); err == nil {
			for _, a := range accts {
				if a.gid == gid {
					admins[a.name] = true
				}
			}
		}
	}
	var service []string
	for _, a := range accts {
		if admins[a.name] && a.name != "root" && a.uid < 1000 && !strings.HasSuffix(a.shell, "bash") && !strings.HasSuffix(a.shell, "sh") {
			service = append(service, a.name)
		}
	}
	names := make([]string, 0, len(admins))
	for n := range admins {
		names = append(names, n)
	}
	slices.Sort(names)
	var problems []string
	if len(service) > 0 {
		problems = append(problems, "service accounts can use sudo: "+strings.Join(service, ", "))
	}
	if len(names) > 5 {
		problems = append(problems, fmt.Sprintf("%d accounts can become root (%s)", len(names), strings.Join(names, ", ")))
	}
	if n := e.nopasswd(); len(n) > 0 {
		problems = append(problems, "sudo needs no password in "+strings.Join(n, ", "))
	}
	if len(problems) > 0 {
		return Outcome{Status: Warn, Detail: strings.Join(problems, "; ") + ".",
			Fix: "Remove people who don't administer this server from the sudo, wheel and admin groups (gpasswd -d name sudo), and replace NOPASSWD rules with ones that ask for a password. Edit sudoers only with visudo."}
	}
	return Outcome{Status: Pass, Detail: fmt.Sprintf("%d accounts can become root: %s.", len(names), strings.Join(names, ", "))}
}

// nopasswd returns the sudoers files that grant NOPASSWD. Without permission
// to read them (usual, since they are mode 0440) it reports nothing.
func (e *Env) nopasswd() []string {
	files := []string{"/etc/sudoers"}
	if entries, err := os.ReadDir(e.path("/etc/sudoers.d")); err == nil {
		for _, en := range entries {
			if !en.IsDir() && !strings.ContainsAny(en.Name(), ".~") {
				files = append(files, "/etc/sudoers.d/"+en.Name())
			}
		}
	}
	var out []string
	for _, f := range files {
		text, err := e.read(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(text, "\n") {
			if l = strings.TrimSpace(l); !strings.HasPrefix(l, "#") && strings.Contains(l, "NOPASSWD") {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func checkSystemFiles(_ context.Context, e *Env) Outcome {
	if o, skip := e.hostSkip(); skip {
		return o
	}
	var bad []string
	checked := 0
	for _, f := range []struct {
		path string
		deny fs.FileMode // permission bits that must not be set
	}{
		{"/etc/passwd", 0o022}, {"/etc/group", 0o022}, {"/etc/shadow", 0o027}, {"/etc/gshadow", 0o027},
		{"/etc/ssh/sshd_config", 0o022}, {"/etc/sudoers", 0o027},
	} {
		info, err := os.Stat(e.path(f.path))
		if err != nil {
			continue
		}
		checked++
		if m := info.Mode().Perm(); m&f.deny != 0 {
			bad = append(bad, fmt.Sprintf("%s is %04o", f.path, m))
		}
	}
	switch {
	case checked == 0:
		return Outcome{Status: Skip, Detail: "None of the system account files could be examined."}
	case len(bad) > 0:
		return Outcome{Status: Fail, Detail: strings.Join(bad, "; ") + ": other users can change them or read password hashes.",
			Fix: "Restore the standard modes: chmod 644 /etc/passwd /etc/group; chmod 640 /etc/shadow /etc/gshadow; chmod 600 /etc/ssh/sshd_config; chmod 440 /etc/sudoers. Then look for how they changed."}
	}
	return Outcome{Status: Pass, Detail: "The account, password and SSH files are only changeable by root."}
}

func checkKernel(_ context.Context, e *Env) Outcome {
	if e.GOOS != "linux" {
		return Outcome{Status: Skip, Detail: "Kernel settings are read from /proc/sys, which only Linux has."}
	}
	var bad []string
	checked := 0
	for _, s := range []struct {
		key  string // under /proc/sys
		min  int
		want string
		why  string
	}{
		{"kernel/randomize_va_space", 2, "2", "address randomization"},
		{"kernel/kptr_restrict", 1, "1 or 2", "hiding kernel addresses from users"},
		{"net/ipv4/tcp_syncookies", 1, "1", "protection from SYN floods"},
		{"net/ipv4/conf/all/rp_filter", 1, "1 or 2", "refusing spoofed source addresses"},
		{"net/ipv4/conf/all/accept_redirects", -1, "0", "ignoring ICMP route redirects"},
		{"net/ipv4/conf/all/accept_source_route", -1, "0", "refusing source-routed packets"},
	} {
		text, err := e.read("/proc/sys/" + s.key)
		if err != nil {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil {
			continue
		}
		checked++
		if (s.min >= 0 && v < s.min) || (s.min < 0 && v != 0) {
			bad = append(bad, fmt.Sprintf("%s is %d, not %s (%s)", strings.ReplaceAll(s.key, "/", "."), v, s.want, s.why))
		}
	}
	switch {
	case checked == 0:
		return Outcome{Status: Skip, Detail: "/proc/sys couldn't be read."}
	case len(bad) > 0:
		return Outcome{Status: Warn, Detail: strings.Join(bad, "; ") + ".",
			Fix: "Put the values in /etc/sysctl.d/99-hardening.conf and apply them with sysctl --system."}
	}
	return Outcome{Status: Pass, Detail: fmt.Sprintf("All %d kernel settings checked have safe values.", checked)}
}

func checkAutoUpdates(ctx context.Context, e *Env) Outcome {
	if o, skip := e.hostSkip(); skip {
		return o
	}
	if conf, err := e.read("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		if strings.Contains(strings.ReplaceAll(conf, " ", ""), `Unattended-Upgrade"1"`) {
			return Outcome{Status: Pass, Detail: "unattended-upgrades is turned on."}
		}
		return Outcome{Status: Warn, Detail: "unattended-upgrades is installed but not turned on.",
			Fix: "Run dpkg-reconfigure -plow unattended-upgrades, and choose Yes."}
	}
	for _, unit := range []string{"dnf-automatic-install.timer", "dnf-automatic.timer", "yum-cron"} {
		if out, _ := e.Exec(ctx, "systemctl", "is-active", unit); strings.TrimSpace(out) == "active" {
			return Outcome{Status: Pass, Detail: unit + " is active."}
		}
	}
	if !e.exists("/etc/apt") && !e.exists("/etc/dnf") && !e.exists("/etc/yum.conf") {
		return Outcome{Status: Skip, Detail: "This isn't an apt or dnf based system, so its update setup can't be checked."}
	}
	return Outcome{Status: Warn, Detail: "Nothing installs security updates automatically, so the server stays exposed to known flaws until someone logs in.",
		Fix: "On Debian or Ubuntu: apt install unattended-upgrades. On Fedora, RHEL and similar: dnf install dnf-automatic, then systemctl enable --now dnf-automatic-install.timer."}
}
