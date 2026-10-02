// SIEMLite: an embedded, OCSF-normalized SIEM backed by SQLite + FTS5.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/ingest"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/retention"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "keys" {
		err = runKeys(os.Args[2:])
	} else if len(os.Args) > 1 && os.Args[1] == "users" {
		err = runUsers(os.Args[2:])
	} else {
		err = run()
	}
	if err != nil {
		slog.Error("siemlite failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	dbPath := flag.String("db", "siemlite.db", "SQLite database path")
	addr := flag.String("addr", "localhost:8443", "HTTPS listen address (there is no plain-HTTP listener)")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM (default: <db dir>/siemlite.crt, self-signed if missing)")
	keyFile := flag.String("tls-key", "", "TLS private key PEM (default: <db dir>/siemlite.key)")
	tlsHosts := flag.String("tls-hosts", "", "extra comma-separated DNS names/IPs for a generated certificate")
	retentionDays := flag.Int("retention-days", 30, "delete events older than this many days")
	sample := flag.Bool("sample", true, "insert sample telemetry and run a demo search at startup")
	flag.Parse()

	if *certFile == "" {
		*certFile = filepath.Join(filepath.Dir(*dbPath), "siemlite.crt")
	}
	if *keyFile == "" {
		*keyFile = filepath.Join(filepath.Dir(*dbPath), "siemlite.key")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := storage.Open(ctx, storage.Options{Path: *dbPath})
	if err != nil {
		return err
	}
	defer db.Close()

	repo := storage.NewRepository(db)
	worker := ingest.New(repo, ingest.Config{BatchSize: 500, FlushInterval: 500 * time.Millisecond})
	engine := search.NewEngine(repo)

	cleaner := retention.New(repo, retention.Config{RetentionDays: *retentionDays, Interval: 24 * time.Hour})
	var wg sync.WaitGroup
	cleanerCtx, cancelCleaner := context.WithCancel(ctx)
	defer cancelCleaner() // early-return paths; the normal path cancels explicitly below
	defer worker.Close()  // idempotent
	wg.Add(1)
	go func() {
		defer wg.Done()
		cleaner.Run(cleanerCtx)
	}()

	if *sample {
		if err := loadSampleAndSearch(ctx, worker, engine); err != nil {
			slog.Warn("sample run failed", "err", err)
		}
	}

	if err := bootstrapAdminUser(ctx, repo); err != nil {
		return err
	}

	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	if host, _, ok := strings.Cut(*addr, ":"); ok && host != "" {
		hosts = append(hosts, host)
	}
	for _, h := range strings.Split(*tlsHosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	fingerprint, generated, err := api.EnsureCertificate(*certFile, *keyFile, hosts)
	if err != nil {
		return err
	}
	if generated {
		slog.Info("generated self-signed TLS certificate", "cert", *certFile, "key", *keyFile)
	}

	srv := api.NewServer(*addr, api.Deps{
		DB: db, Repo: repo, Ingest: worker, Search: engine,
		Auth: auth.New(repo, nil),
	})
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start(*certFile, *keyFile) }()
	slog.Info("SIEMLite listening (HTTPS only)", "url", "https://"+*addr, "db", *dbPath,
		"retention_days", *retentionDays, "cert_sha256", fingerprint)

	var runErr error
	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case runErr = <-serveErr:
	}

	// Stop intake first, then flush the queue, then close the database.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = err
	}
	worker.Close()
	cancelCleaner()
	wg.Wait()
	return runErr
}

// loadSampleAndSearch ingests demo events through the batching pipeline and
// then runs an FTS5 search over them.
func loadSampleAndSearch(ctx context.Context, worker *ingest.Worker, engine *search.Engine) error {
	now := time.Now()
	ev := func(ago time.Duration, cat, class, sev int, msg, src, dst, user string) *ocsf.Event {
		e := &ocsf.Event{
			Time: now.Add(-ago).UnixMilli(), CategoryUID: cat, ClassUID: class, ActivityID: 1,
			SeverityID: sev, Message: msg,
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "siemlite-sample"}},
		}
		if src != "" {
			e.SrcEndpoint = &ocsf.Endpoint{IP: src}
		}
		if dst != "" {
			e.DstEndpoint = &ocsf.Endpoint{IP: dst}
		}
		if user != "" {
			e.Actor = &ocsf.Actor{User: &ocsf.User{Name: user}}
		}
		return e
	}

	samples := []*ocsf.Event{
		ev(50*time.Minute, ocsf.CategoryIAM, 3002, ocsf.SeverityMedium, "Failed password for root from 203.0.113.7 via ssh", "203.0.113.7", "10.0.0.5", "root"),
		ev(48*time.Minute, ocsf.CategoryIAM, 3002, ocsf.SeverityMedium, "Failed password for invalid user admin via ssh", "203.0.113.7", "10.0.0.5", "admin"),
		ev(45*time.Minute, ocsf.CategoryIAM, 3002, ocsf.SeverityHigh, "Multiple failed ssh logins, possible brute force", "203.0.113.7", "10.0.0.5", ""),
		ev(40*time.Minute, ocsf.CategoryIAM, 3002, ocsf.SeverityInformational, "Accepted publickey for deploy via ssh", "198.51.100.20", "10.0.0.5", "deploy"),
		ev(30*time.Minute, ocsf.CategoryNetworkActivity, 4001, ocsf.SeverityLow, "Firewall allowed outbound HTTPS connection", "10.0.0.12", "93.184.216.34", ""),
		ev(20*time.Minute, ocsf.CategoryNetworkActivity, 4001, ocsf.SeverityHigh, "Firewall blocked connection to known C2 address", "10.0.0.31", "192.0.2.66", ""),
		ev(10*time.Minute, ocsf.CategorySystemActivity, 1007, ocsf.SeverityCritical, "Process injection detected in lsass.exe", "", "", "svc-backup"),
		ev(5*time.Minute, ocsf.CategoryApplicationActivity, 6003, ocsf.SeverityInformational, "GET /api/orders 200 12ms", "10.0.0.40", "10.0.0.8", "alice"),
	}
	for _, e := range samples {
		if err := worker.Submit(ctx, e); err != nil {
			return fmt.Errorf("submit sample: %w", err)
		}
	}

	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := worker.Drain(drainCtx); err != nil {
		return fmt.Errorf("drain: %w", err)
	}

	res, err := engine.Search(ctx, search.Query{
		Start: now.Add(-2 * time.Hour),
		End:   now,
		Text:  `failed AND ssh`,
		Limit: 10,
	})
	if err != nil {
		return err
	}
	fmt.Printf("FTS5 demo: %q matched %d events in %.2fms\n", "failed AND ssh", res.Count, res.TookMs)
	for _, r := range res.Events {
		out, _ := json.Marshal(map[string]any{
			"id": r.ID, "time": time.UnixMilli(r.Timestamp).Format(time.RFC3339),
			"severity": r.SeverityID, "src_ip": r.SrcIP, "user": r.UserName,
		})
		fmt.Println(" ", string(out))
	}
	return nil
}

// bootstrapAdminUser creates a first admin account when no users exist, so a
// fresh install is never open and never locked out. The password is generated
// and printed once.
func bootstrapAdminUser(ctx context.Context, repo *storage.Repository) error {
	n, err := repo.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	password, err := auth.GeneratePassword()
	if err != nil {
		return err
	}
	if _, err := auth.CreateUser(ctx, repo, "admin", password, auth.RoleAdmin); err != nil {
		return err
	}
	fmt.Printf("\nNo users exist. Created an admin account (password shown once, store it safely):\n\n"+
		"  username: admin\n  password: %s\n\n"+
		"Add people with: siemlite users create -username alice -role analyst\n"+
		"Create an API key for an app that sends logs with: siemlite keys create -name myapp\n\n", password)
	return nil
}

// openForCLI opens the database for a management subcommand.
func openForCLI(dbPath string) (*storage.DB, *storage.Repository, error) {
	db, err := storage.Open(context.Background(), storage.Options{Path: dbPath, ReadConns: 2})
	if err != nil {
		return nil, nil, err
	}
	return db, storage.NewRepository(db), nil
}

// runKeys implements `siemlite keys create|list|revoke`. API keys are for
// applications that send logs; they cannot search or sign in.
func runKeys(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: siemlite keys <create|list|revoke> [flags]")
	}
	cmd, rest := args[0], args[1:]

	fs := flag.NewFlagSet("keys "+cmd, flag.ContinueOnError)
	dbPath := fs.String("db", "siemlite.db", "SQLite database path")
	name := fs.String("name", "", "key name, e.g. the app it belongs to (create)")
	id := fs.Int64("id", 0, "key id (revoke)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	db, repo, err := openForCLI(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()

	switch cmd {
	case "create":
		kid, key, err := auth.CreateKey(ctx, repo, *name)
		if err != nil {
			return err
		}
		fmt.Printf("Created API key %d (%s). It can only send logs. Shown once, store it safely:\n\n  %s\n", kid, *name, key)
	case "list":
		keys, err := repo.ListKeys(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%-4s %-24s %-20s %s\n", "ID", "NAME", "CREATED", "STATUS")
		for _, k := range keys {
			status := "active"
			if k.RevokedAt != nil {
				status = "revoked"
			}
			fmt.Printf("%-4d %-24s %-20s %s\n", k.ID, k.Name,
				time.UnixMilli(k.CreatedAt).Format("2006-01-02 15:04:05"), status)
		}
	case "revoke":
		ok, err := repo.RevokeKey(ctx, *id, time.Now().UnixMilli())
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no active key with id %d", *id)
		}
		fmt.Printf("Revoked key %d\n", *id)
	default:
		return fmt.Errorf("unknown keys command %q (want create, list or revoke)", cmd)
	}
	return nil
}

// runUsers implements `siemlite users create|list|passwd|delete`.
func runUsers(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: siemlite users <create|list|passwd|delete> [flags]")
	}
	cmd, rest := args[0], args[1:]

	fs := flag.NewFlagSet("users "+cmd, flag.ContinueOnError)
	dbPath := fs.String("db", "siemlite.db", "SQLite database path")
	username := fs.String("username", "", "username")
	role := fs.String("role", auth.RoleAnalyst, "admin (search + add logs) or analyst (search only) (create)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	db, repo, err := openForCLI(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()

	switch cmd {
	case "create":
		pw, err := readNewPassword()
		if err != nil {
			return err
		}
		if _, err := auth.CreateUser(ctx, repo, *username, pw, *role); err != nil {
			if errors.Is(err, storage.ErrUserExists) {
				return fmt.Errorf("user %q already exists", *username)
			}
			return err
		}
		fmt.Printf("Created %s %q\n", *role, *username)
	case "passwd":
		pw, err := readNewPassword()
		if err != nil {
			return err
		}
		if err := auth.SetPassword(ctx, repo, *username, pw); err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return fmt.Errorf("no user %q", *username)
			}
			return err
		}
		fmt.Printf("Password updated for %q; their sessions were ended\n", *username)
	case "delete":
		ok, err := repo.DeleteUser(ctx, *username)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no user %q", *username)
		}
		fmt.Printf("Deleted user %q\n", *username)
	case "list":
		users, err := repo.ListUsers(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%-4s %-24s %-8s %s\n", "ID", "USERNAME", "ROLE", "CREATED")
		for _, u := range users {
			fmt.Printf("%-4d %-24s %-8s %s\n", u.ID, u.Username, u.Role,
				time.UnixMilli(u.CreatedAt).Format("2006-01-02 15:04:05"))
		}
	default:
		return fmt.Errorf("unknown users command %q (want create, list, passwd or delete)", cmd)
	}
	return nil
}

// readNewPassword prompts twice without echo on a terminal, or reads one line
// from stdin when piped (for scripts), so passwords never appear in argv.
func readNewPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprintf(os.Stderr, "Password (min %d characters): ", auth.MinPasswordLen)
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}
