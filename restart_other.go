//go:build !unix

package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// restartSelf starts a fresh copy of SIEMLite with the same arguments and
// environment, then exits, since Windows can't replace a running process.
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	slog.Info("restarting SIEMLite")
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr, cmd.Env = os.Stdin, os.Stdout, os.Stderr, os.Environ()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	os.Exit(0)
	return nil
}
