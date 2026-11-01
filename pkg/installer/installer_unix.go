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
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=" + dir}
	cmd.Stdin = strings.NewReader(stdin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	old := syscall.Umask(0o077)
	err = cmd.Run()
	syscall.Umask(old)
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
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return os.Chown(path, uid, gid)
}
