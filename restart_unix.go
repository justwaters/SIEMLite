//go:build unix

package main

import (
	"fmt"
	"log/slog"
	"os"
	"syscall"
)

// restartSelf replaces this process with a fresh copy of itself, with the
// same arguments and environment, once everything has shut down. It works
// the same under Docker, systemd or a plain shell.
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	slog.Info("restarting SIEMLite")
	return syscall.Exec(exe, os.Args, os.Environ())
}
