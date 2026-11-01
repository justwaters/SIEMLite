package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"siemlite/pkg/auth"
	"siemlite/pkg/installer"
)

// runInstall implements `siemlite install`: install or update this program as
// a systemd service on Linux, or remove it with --uninstall. It is a
// subcommand rather than something the program does by itself, so running
// ./siemlite to try it never touches the system.
func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var o installer.Options
	fs.BoolVar(&o.DryRun, "dry-run", false, "print what would be done and change nothing")
	fs.BoolVar(&o.Uninstall, "uninstall", false, "remove the service and program; keeps the data, settings and user")
	fs.BoolVar(&o.Purge, "purge", false, "with --uninstall: also delete the data, settings and user")
	fs.BoolVar(&o.NoSyslog, "no-syslog", false, "first install: leave the syslog listeners (port 514) off")
	fs.BoolVar(&o.AllowDowngrade, "allow-downgrade", false, "install over a newer version")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: sudo siemlite install [--dry-run] [--no-syslog] [--allow-downgrade]\n       sudo siemlite install --uninstall [--purge] [--dry-run]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("install: unexpected argument %q", fs.Arg(0))
	}
	env := installer.NewEnv(startExe, version(), os.Stdout, auth.GeneratePassword)
	err := env.Run(context.Background(), o)
	var refusal installer.Refusal
	if errors.As(err, &refusal) {
		fmt.Fprintln(os.Stderr, "siemlite install: nothing was changed:", refusal.Reason)
		os.Exit(1)
	}
	return err
}
