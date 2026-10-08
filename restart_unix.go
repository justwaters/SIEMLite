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
	exe := startExe
	if exe == "" {
		return fmt.Errorf("restart: can't tell where SIEMLite's program file is")
	}
	slog.Info("restarting SIEMLite")
	return syscall.Exec(exe, os.Args, os.Environ())
}

// execProgram replaces this process with the program at path, with the same
// arguments and environment.
func execProgram(path string) error {
	return syscall.Exec(path, append([]string{path}, os.Args[1:]...), os.Environ())
}
