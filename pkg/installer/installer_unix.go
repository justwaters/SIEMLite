//go:build unix

package installer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// runAs is the real ExecAs: the program runs as the named user, in dir, with
// stdin, a minimal environment and a restrictive umask (so files it creates,
// like the database, are 0600).
func runAs(ctx context.Context, name, dir, stdin, prog string, args ...string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	uid, gid, err := parseIDs(u)
	if err != nil {
		return "", err
	}
	// The service user's own groups (Go clears them when none are given).
	groups, err := groupIDs(u)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=" + dir}
	cmd.Stdin = strings.NewReader(stdin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	// The umask is process-wide, which is fine: the installer runs one step at a time.
	err = func() error {
		defer syscall.Umask(syscall.Umask(0o077))
		return cmd.Run()
	}()
	if err != nil {
		return out.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// chownTo makes the user and its group own path.
func chownTo(path, name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, gid, err := parseIDs(u)
	if err != nil {
		return err
	}
	return os.Chown(path, int(uid), int(gid))
}

// parseIDs reads the numeric uid and gid of u. A value that does not parse is
// an error: it must never fall back to 0, which is root.
func parseIDs(u *user.User) (uid, gid uint32, err error) {
	u64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("user %q has an invalid uid %q: %w", u.Username, u.Uid, err)
	}
	g64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("user %q has an invalid gid %q: %w", u.Username, u.Gid, err)
	}
	return uint32(u64), uint32(g64), nil
}

// groupIDs lists the numeric ids of every group u is in; one that does not
// parse is an error, never a silent 0 (root).
func groupIDs(u *user.User) ([]uint32, error) {
	names, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(names))
	for _, n := range names {
		g, err := strconv.ParseUint(n, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("user %q is in a group with an invalid id %q: %w", u.Username, n, err)
		}
		out = append(out, uint32(g))
	}
	return out, nil
}
