// SIEMLite: an embedded, OCSF-normalized SIEM backed by SQLite + FTS5.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"siemlite/api"
	"siemlite/pkg/ai"
	"siemlite/pkg/auth"
	"siemlite/pkg/backup"
	"siemlite/pkg/enrich"
	"siemlite/pkg/ingest"
	"siemlite/pkg/intel"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
	"siemlite/pkg/retention"
	"siemlite/pkg/sample"
	"siemlite/pkg/search"
	"siemlite/pkg/sources"
	"siemlite/pkg/storage"
	"siemlite/pkg/syslogd"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "keys" {
		err = runKeys(os.Args[2:])
	} else if len(os.Args) > 1 && os.Args[1] == "users" {
		err = runUsers(os.Args[2:])
	} else if len(os.Args) > 1 && os.Args[1] == "intel" {
		err = runIntel(os.Args[2:])
	} else if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		err = runHealthcheck(os.Args[2:])
	} else if len(os.Args) > 1 && os.Args[1] == "backups" {
		err = runBackups(os.Args[2:])
	} else {
		err = run()
		if errors.Is(err, errRestart) {
			err = restartSelf()
		}
	}
	if err != nil {
		slog.Error("siemlite failed", "err", err)
		os.Exit(1)
	}
}

// errRestart asks main to start SIEMLite again, after a restore.
var errRestart = errors.New("restart requested")

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

func run() error {
	dbPath := flag.String("db", "siemlite.db", "SQLite database path")
	addr := flag.String("addr", "localhost:8443", "HTTPS listen address (there is no plain-HTTP listener)")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM (default: <db dir>/siemlite.crt, self-signed if missing)")
	keyFile := flag.String("tls-key", "", "TLS private key PEM (default: <db dir>/siemlite.key)")
	tlsHosts := flag.String("tls-hosts", "", "extra comma-separated DNS names/IPs for a generated certificate")
	retentionDays := flag.Int("retention-days", 30, "delete events older than this many days")
	loadSample := flag.Bool("sample", false, "load sample data at startup if it is not loaded (same as the UI's Sample data switch)")
	geoCity := flag.String("geoip-city", "", "MaxMind/DB-IP City or Country .mmdb for IP geolocation")
	geoASN := flag.String("geoip-asn", "", "MaxMind/DB-IP ASN .mmdb for IP autonomous system lookup")
	var feeds feedFlag
	flag.Var(&feeds, "intel-feed", "threat intel feed to download, as name=https://url (repeatable)")
	intelRefresh := flag.Duration("intel-refresh", 6*time.Hour, "how often to re-download -intel-feed feeds")
	syslogUDP := flag.String("syslog-udp", "", "syslog UDP listen address, e.g. :514 (off when empty)")
	syslogTCP := flag.String("syslog-tcp", "", "syslog TCP listen address, e.g. :514 (off when empty)")
	syslogTLS := flag.String("syslog-tls", "", "syslog over TLS listen address, e.g. :6514 (off when empty)")
	syslogAllow := flag.String("syslog-allow", "", "comma-separated networks allowed to send syslog (default: loopback and private ranges)")
	aiURL := flag.String("ai-url", "", "Ollama server for AI parser help, e.g. http://ollama:11434 (off when empty)")
	aiModel := flag.String("ai-model", ai.DefaultModel, "Ollama model for AI parser help")
	backupDir := flag.String("backup-dir", "", "folder for database backups (default: <db dir>/backups)")
	if err := flagsFromEnv(flag.CommandLine); err != nil {
		return err
	}
	flag.Parse()

	allow, err := parsePrefixes(*syslogAllow)
	if err != nil {
		return fmt.Errorf("-syslog-allow: %w", err)
	}

	if *certFile == "" {
		*certFile = filepath.Join(filepath.Dir(*dbPath), "siemlite.crt")
	}
	if *keyFile == "" {
		*keyFile = filepath.Join(filepath.Dir(*dbPath), "siemlite.key")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *backupDir == "" {
		*backupDir = filepath.Join(filepath.Dir(*dbPath), "backups")
	}
	// A restore chosen on the System page is applied before the database opens.
	if _, err := backup.ApplyPendingRestore(*dbPath, nil); err != nil {
		slog.Error("restore not applied; starting with the current database", "err", err)
	}
	started := time.Now()
	db, err := storage.Open(ctx, storage.Options{Path: *dbPath})
	if err != nil {
		return err
	}
	defer db.Close()

	repo := storage.NewRepository(db)

	// Enrichment runs on every event before it is stored.
	intelSvc := intel.NewService(repo, intel.Config{Feeds: feeds, FeedInterval: *intelRefresh})
	if err := intelSvc.Load(ctx); err != nil {
		return fmt.Errorf("load threat intel: %w", err)
	}
	enrichers := enrich.Chain{}
	var geo *enrich.GeoIP
	if *geoCity != "" || *geoASN != "" {
		if geo, err = enrich.OpenGeoIP(*geoCity, *geoASN, nil); err != nil {
			return err
		}
		defer geo.Close()
		enrichers = append(enrichers, geo)
		slog.Info("GeoIP enrichment enabled", "city", *geoCity, "asn", *geoASN)
	}
	enrichers = append(enrichers, intelSvc.Matcher)

	worker := ingest.New(repo, ingest.Config{BatchSize: 500, FlushInterval: 500 * time.Millisecond, Enricher: enrichers})
	engine := search.NewEngine(repo)

	cleaner := retention.New(repo, retention.Config{RetentionDays: *retentionDays, Interval: 24 * time.Hour})
	var wg sync.WaitGroup
	bgCtx, cancelBackground := context.WithCancel(ctx)
	defer cancelBackground() // early-return paths; the normal path cancels explicitly below
	defer worker.Close()     // idempotent
	wg.Add(2)
	go func() {
		defer wg.Done()
		cleaner.Run(bgCtx)
	}()
	go func() {
		defer wg.Done()
		intelSvc.Run(bgCtx)
	}()
	if geo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			geo.Run(bgCtx, time.Hour)
		}()
	}

	router := sources.New(repo)
	authn := auth.New(repo, nil)
	var aiClient *ai.Client
	if *aiURL != "" {
		aiClient = ai.New(*aiURL, *aiModel, nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			aiClient.Prepare(bgCtx)
		}()
		slog.Info("AI parser help enabled", "url", *aiURL, "model", *aiModel)
	}

	backups, err := backup.New(*backupDir, db, repo, nil)
	if err != nil {
		return err
	}
	backups.CleanTemp()
	wg.Add(1)
	go func() {
		defer wg.Done()
		backups.Run(bgCtx)
	}()
	restartCh := make(chan struct{}, 1)

	samples := sample.NewManager(repo, worker)
	if *loadSample {
		if st, err := samples.Status(ctx); err == nil && !st.Enabled {
			if st, err = samples.Enable(ctx); err != nil {
				slog.Warn("loading sample data failed", "err", err)
			} else {
				slog.Info("sample data loaded", "events", st.Events)
			}
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

	var syslogSrv *syslogd.Server
	if *syslogUDP != "" || *syslogTCP != "" || *syslogTLS != "" {
		syslogID, err := router.Builtin(ctx, storage.SourceSyslog)
		if err != nil {
			return err
		}
		cfg := syslogd.Config{
			UDPAddr: *syslogUDP, TCPAddr: *syslogTCP, TLSAddr: *syslogTLS, Allow: allow,
			Parse: func(ctx context.Context, line string) (*ocsf.Event, map[string]string, error) {
				return router.Parse(ctx, syslogID, line, parser.Defaults{})
			},
			Submit: func(ctx context.Context, ev *ocsf.Event, fields map[string]string) error {
				authn.TouchSource(ctx, syslogID)
				return worker.SubmitWith(ctx, ev, ingest.SubmitOptions{SourceID: syslogID, Fields: fields})
			},
		}
		if *syslogTLS != "" {
			pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				return fmt.Errorf("syslog TLS certificate: %w", err)
			}
			cfg.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		}
		if syslogSrv, err = syslogd.Start(cfg); err != nil {
			return fmt.Errorf("start syslog listener: %w", err)
		}
		defer syslogSrv.Close() // idempotent
		allowed := *syslogAllow
		if allowed == "" {
			allowed = "loopback and private networks"
		}
		slog.Info("syslog listening", "udp", *syslogUDP, "tcp", *syslogTCP, "tls", *syslogTLS, "allow", allowed)
	}

	srv := api.NewServer(*addr, api.Deps{
		DB: db, Repo: repo, Ingest: worker, Search: engine,
		Auth: authn, Intel: intelSvc, Syslog: syslogSrv, Sample: samples, Router: router, AI: aiClient,
		Backups: backups, Started: started,
		Restart: func() {
			select {
			case restartCh <- struct{}{}:
			default:
			}
		},
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
	case <-restartCh:
		slog.Info("restarting to apply a restore")
		runErr = errRestart
	}

	// Stop intake first, then flush the queue, then close the database.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && (runErr == nil || runErr == errRestart) && err != context.DeadlineExceeded {
		runErr = err
	}
	if syslogSrv != nil {
		syslogSrv.Close()
	}
	worker.Close()
	cancelBackground()
	wg.Wait()
	return runErr
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
		"Add people with: siemlite users create -username alice -role standard\n"+
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
		kid, key, err := auth.CreateKey(ctx, repo, *name, nil)
		if err != nil {
			return err
		}
		fmt.Printf("Created source %d (%s). Its access token can only send logs. Shown once, store it safely:\n\n  %s\n", kid, *name, key)
	case "list":
		srcs, err := repo.ListSources(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%-4s %-24s %-20s %-20s %s\n", "ID", "NAME", "CREATED", "LAST USED", "STATUS")
		for _, k := range srcs {
			if k.Kind != storage.SourceToken {
				continue
			}
			status, used := "active", "never"
			if k.RevokedAt != nil {
				status = "revoked"
			}
			if k.LastUsedAt != nil {
				used = time.UnixMilli(*k.LastUsedAt).Format("2006-01-02 15:04:05")
			}
			fmt.Printf("%-4d %-24s %-20s %-20s %s\n", k.ID, k.Name,
				time.UnixMilli(k.CreatedAt).Format("2006-01-02 15:04:05"), used, status)
		}
	case "revoke":
		ok, err := repo.RevokeSource(ctx, *id, time.Now().UnixMilli())
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
	role := fs.String("role", auth.RoleStandard, "admin (everything) or standard (search) (create)")
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

// flagsFromEnv sets each flag from SIEMLITE_<NAME> (e.g. -geoip-city from
// SIEMLITE_GEOIP_CITY) when that variable is non-empty, so containers can be
// configured with an env file. Flags on the command line still win.
// -intel-feed takes several feeds separated by spaces or newlines.
func flagsFromEnv(fs *flag.FlagSet) error {
	var err error
	fs.VisitAll(func(f *flag.Flag) {
		env := "SIEMLITE_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		v := strings.TrimSpace(os.Getenv(env))
		if v == "" || err != nil {
			return
		}
		values := []string{v}
		if _, repeatable := f.Value.(*feedFlag); repeatable {
			values = strings.Fields(v)
		}
		for _, one := range values {
			if e := f.Value.Set(one); e != nil {
				err = fmt.Errorf("%s: %w", env, e)
				return
			}
		}
	})
	return err
}

// runHealthcheck implements `siemlite healthcheck`, for container health
// checks where no curl is available. It exits non-zero unless /health
// answers 200. The certificate is not verified: this only checks liveness.
func runHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "https://127.0.0.1:8443/health", "health endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(*url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: %s", resp.Status)
	}
	return nil
}

// runBackups implements `siemlite backups list|create|restore`. A restore is
// applied the next time SIEMLite starts.
func runBackups(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: siemlite backups <list|create|restore> [flags]")
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet("backups "+cmd, flag.ContinueOnError)
	dbPath := fs.String("db", "siemlite.db", "SQLite database path")
	dir := fs.String("backup-dir", "", "backups folder (default: <db dir>/backups)")
	name := fs.String("name", "", "backup to restore (restore)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *dir == "" {
		*dir = filepath.Join(filepath.Dir(*dbPath), "backups")
	}
	db, repo, err := openForCLI(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	m, err := backup.New(*dir, db, repo, nil)
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch cmd {
	case "list":
		list, err := m.List()
		if err != nil {
			return err
		}
		fmt.Printf("%-48s %-15s %-20s %s\n", "NAME", "KIND", "CREATED", "SIZE")
		for _, b := range list {
			fmt.Printf("%-48s %-15s %-20s %.1f MB\n", b.Name, b.Kind, time.UnixMilli(b.CreatedAt).Format("2006-01-02 15:04:05"), float64(b.Size)/1048576)
		}
	case "create":
		b, err := m.Create(ctx, backup.Manual)
		if err != nil {
			return err
		}
		fmt.Printf("Created %s (%.1f MB) in %s\n", b.Name, float64(b.Size)/1048576, m.Dir())
	case "restore":
		safety, err := m.StageRestore(ctx, *name)
		if err != nil {
			return err
		}
		fmt.Printf("The current database was saved as %s.\nRestart SIEMLite to restore %s.\n", safety.Name, *name)
	default:
		return fmt.Errorf("unknown backups command %q (want list, create or restore)", cmd)
	}
	return nil
}

// feedFlag collects repeated -intel-feed name=url flags.
type feedFlag []intel.Feed

func (f *feedFlag) String() string {
	parts := make([]string, len(*f))
	for i, fd := range *f {
		parts[i] = fd.Name + "=" + fd.URL
	}
	return strings.Join(parts, ",")
}

func (f *feedFlag) Set(v string) error {
	name, url, ok := strings.Cut(v, "=")
	name, url = strings.TrimSpace(name), strings.TrimSpace(url)
	if !ok || name == "" || url == "" {
		return errors.New("want name=https://url")
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return fmt.Errorf("feed %s: URL must start with https:// or http://", name)
	}
	*f = append(*f, intel.Feed{Name: name, URL: url})
	return nil
}

// parsePrefixes parses comma-separated CIDRs or bare IPs.
func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			a, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP or CIDR", part)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", part)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// runIntel implements `siemlite intel import|add|list|delete`.
func runIntel(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: siemlite intel <import|add|list|delete> [flags]")
	}
	cmd, rest := args[0], args[1:]

	fs := flag.NewFlagSet("intel "+cmd, flag.ContinueOnError)
	dbPath := fs.String("db", "siemlite.db", "SQLite database path")
	source := fs.String("source", "", "indicator source name, e.g. feodo or manual")
	file := fs.String("file", "", "feed file to import, one indicator per line; - for stdin (import)")
	url := fs.String("url", "", "feed URL to download and import (import)")
	value := fs.String("value", "", "indicator: an IP, CIDR, domain, URL or hash (add)")
	typ := fs.String("type", "", "ip, cidr, domain or hash (default: detect)")
	desc := fs.String("description", "", "description stored with the indicators")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	db, repo, err := openForCLI(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UnixMilli()
	needSource := func() error {
		if strings.TrimSpace(*source) == "" {
			return errors.New("-source is required")
		}
		return nil
	}

	switch cmd {
	case "import":
		if err := needSource(); err != nil {
			return err
		}
		var r io.Reader
		switch {
		case *url != "" && *file != "":
			return errors.New("use -file or -url, not both")
		case *url != "":
			if *typ != "" || *desc != "" {
				return errors.New("-type and -description apply to -file imports only")
			}
			n, skipped, err := intel.FetchFeed(ctx, &http.Client{Timeout: 2 * time.Minute}, repo, intel.Feed{Name: *source, URL: *url})
			if err != nil {
				return err
			}
			fmt.Printf("Source %q now has %d indicators (%d lines skipped)\n", *source, n, skipped)
			return nil
		case *file == "-":
			r = os.Stdin
		case *file != "":
			f, err := os.Open(*file)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		default:
			return errors.New("-file or -url is required")
		}
		inds, skipped, err := intel.ParseFeed(r, *typ, *source, *desc)
		if err != nil {
			return err
		}
		if len(inds) == 0 {
			return fmt.Errorf("no valid indicators found (%d lines skipped)", skipped)
		}
		n, err := repo.ReplaceIndicators(ctx, *source, inds, now)
		if err != nil {
			return err
		}
		fmt.Printf("Source %q now has %d indicators (%d lines skipped). A running server picks this up within 30s.\n", *source, n, skipped)
	case "add":
		if err := needSource(); err != nil {
			return err
		}
		t, v, err := intel.Normalize(*typ, *value)
		if err != nil {
			return err
		}
		if _, err := repo.AddIndicators(ctx, []storage.Indicator{{Type: t, Value: v, Source: *source, Description: *desc}}, now); err != nil {
			return err
		}
		fmt.Printf("Added %s %s to %q\n", t, v, *source)
	case "list":
		srcs, err := repo.ListIntelSources(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%-24s %-10s %s\n", "SOURCE", "COUNT", "UPDATED")
		for _, s := range srcs {
			fmt.Printf("%-24s %-10d %s\n", s.Source, s.Count, time.UnixMilli(s.UpdatedAt).Format("2006-01-02 15:04:05"))
		}
	case "delete":
		if err := needSource(); err != nil {
			return err
		}
		n, err := repo.DeleteIndicatorSource(ctx, *source)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("no indicators from source %q", *source)
		}
		fmt.Printf("Deleted %d indicators from %q\n", n, *source)
	default:
		return fmt.Errorf("unknown intel command %q (want import, add, list or delete)", cmd)
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
