// Package backup creates, lists, prunes and restores compressed copies of
// the SIEMLite database.
//
// A backup is a VACUUM INTO snapshot, gzipped, named
// siemlite-YYYYMMDD-HHMMSS-<kind>.db.gz (UTC). Restoring never touches the
// open database: the chosen backup is checked and unpacked next to the
// database as <db>.restore, a backup of the current database is made first,
// and the swap happens on the next start (ApplyPendingRestore), after which
// the normal upgrade brings an older backup up to date.
package backup

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"siemlite/pkg/storage"
)

// Kinds of backup.
const (
	Manual        = "manual"
	Automatic     = "auto"
	BeforeRestore = "before-restore"
	Uploaded      = "uploaded"
)

// Setting keys.
const (
	keyInterval = "backup_interval_hours"
	keyKeep     = "backup_keep"
)

var nameRe = regexp.MustCompile(`^siemlite-(\d{8}-\d{6})(?:-(\d+))?-(manual|auto|before-restore|uploaded)\.db\.gz$`)

// Backup describes one backup file.
type Backup struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	CreatedAt int64  `json:"created_at"`
	Size      int64  `json:"size"`
}

// Settings are the automatic backup schedule.
type Settings struct {
	IntervalHours int `json:"interval_hours"` // 0 = off
	Keep          int `json:"keep"`           // automatic backups kept
}

// Status reports the background job.
type Status struct {
	Running   bool   `json:"running"`
	Kind      string `json:"kind,omitempty"`
	StartedAt int64  `json:"started_at,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// Store is what the manager needs from the database.
type Store interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Snapshotter copies the live database to a file.
type Snapshotter interface {
	SnapshotTo(ctx context.Context, dest string) error
	Path() string
}

// Manager runs backups. One backup runs at a time.
type Manager struct {
	dir   string
	db    Snapshotter
	store Store
	log   *slog.Logger
	now   func() time.Time

	jobMu  sync.Mutex // held while a backup or restore runs
	stMu   sync.Mutex
	status Status
}

// ErrBusy means another backup is running.
var ErrBusy = errors.New("a backup is already running; try again when it finishes")

// ErrNotFound means no backup has that name.
var ErrNotFound = errors.New("no backup with that name")

// New returns a manager storing backups in dir (created if needed).
func New(dir string, db Snapshotter, store Store, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("backups folder: %w", err)
	}
	return &Manager{dir: dir, db: db, store: store, log: log, now: time.Now}, nil
}

// Dir is the backups folder.
func (m *Manager) Dir() string { return m.dir }

// Status returns the background job state.
func (m *Manager) Status() Status {
	m.stMu.Lock()
	defer m.stMu.Unlock()
	return m.status
}

// List returns backups, newest first.
func (m *Manager) List() ([]Backup, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	out := []Backup{}
	for _, e := range entries {
		b, ok := parse(e.Name())
		if !ok || e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil {
			b.Size = info.Size()
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].Name > out[j].Name
	})
	return out, nil
}

func parse(name string) (Backup, bool) {
	m := nameRe.FindStringSubmatch(name)
	if m == nil {
		return Backup{}, false
	}
	t, err := time.Parse("20060102-150405", m[1])
	if err != nil {
		return Backup{}, false
	}
	return Backup{Name: name, Kind: m[3], CreatedAt: t.UnixMilli()}, true
}

// newName picks an unused file name for a backup of kind made now.
func (m *Manager) newName(kind string) string {
	stamp := m.now().UTC().Format("20060102-150405")
	name := fmt.Sprintf("siemlite-%s-%s.db.gz", stamp, kind)
	for i := 2; fileExists(filepath.Join(m.dir, name)); i++ {
		name = fmt.Sprintf("siemlite-%s-%d-%s.db.gz", stamp, i, kind)
	}
	return name
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// Start begins a backup in the background.
func (m *Manager) Start(kind string) error {
	if !m.jobMu.TryLock() {
		return ErrBusy
	}
	m.setStatus(Status{Running: true, Kind: kind, StartedAt: m.now().UnixMilli()})
	go func() {
		defer m.jobMu.Unlock()
		b, err := m.create(context.Background(), kind)
		st := Status{Kind: kind}
		if err != nil {
			st.LastError = err.Error()
			m.log.Error("backup failed", "kind", kind, "err", err)
		} else {
			st.LastName = b.Name
		}
		m.setStatus(st)
	}()
	return nil
}

func (m *Manager) setStatus(s Status) {
	m.stMu.Lock()
	m.status = s
	m.stMu.Unlock()
}

// Create makes a backup and waits for it.
func (m *Manager) Create(ctx context.Context, kind string) (Backup, error) {
	if !m.jobMu.TryLock() {
		return Backup{}, ErrBusy
	}
	defer m.jobMu.Unlock()
	return m.create(ctx, kind)
}

func (m *Manager) create(ctx context.Context, kind string) (Backup, error) {
	began := m.now()
	name := m.newName(kind)
	snap := filepath.Join(m.dir, "."+name+".snapshot")
	defer os.Remove(snap)
	if err := m.db.SnapshotTo(ctx, snap); err != nil {
		return Backup{}, err
	}
	if err := gzipFile(snap, filepath.Join(m.dir, name)); err != nil {
		return Backup{}, err
	}
	b, _ := parse(name)
	if info, err := os.Stat(filepath.Join(m.dir, name)); err == nil {
		b.Size = info.Size()
	}
	m.log.Info("backup created", "name", name, "bytes", b.Size, "took", time.Since(began).Round(time.Millisecond))
	if kind == Automatic {
		m.prune(ctx)
	}
	return b, nil
}

// gzipFile compresses src into dst, writing to a temporary name first so a
// half-written backup never appears in the list.
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw, _ := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if _, err = io.Copy(zw, in); err == nil {
		err = zw.Close()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("compress backup: %w", err)
	}
	return os.Rename(tmp, dst)
}

// gunzipFile unpacks a backup into dst.
func gunzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("the backup isn't a gzip file: %w", err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, zr); err == nil {
		err = zr.Close()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return fmt.Errorf("unpack backup: %w", err)
	}
	return nil
}

// path returns the file for a backup name, refusing anything that isn't
// a backup name (so no path tricks reach the file system).
func (m *Manager) path(name string) (string, error) {
	if _, ok := parse(name); !ok {
		return "", ErrNotFound
	}
	p := filepath.Join(m.dir, name)
	if !fileExists(p) {
		return "", ErrNotFound
	}
	return p, nil
}

// Delete removes a backup.
func (m *Manager) Delete(name string) error {
	p, err := m.path(name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// Open returns a backup for download.
func (m *Manager) Open(name string) (*os.File, error) {
	p, err := m.path(name)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// Upload stores a backup made elsewhere (gzipped or a plain .db file) after
// checking it is a sound SIEMLite database.
func (m *Manager) Upload(ctx context.Context, r io.Reader) (Backup, error) {
	name := m.newName(Uploaded)
	raw := filepath.Join(m.dir, "."+name+".upload")
	defer os.Remove(raw)
	out, err := os.OpenFile(raw, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Backup{}, err
	}
	_, err = io.Copy(out, r)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Backup{}, fmt.Errorf("receive upload: %w", err)
	}
	plain := raw
	if isGzip(raw) {
		plain = raw + ".db"
		defer os.Remove(plain)
		if err := gunzipFile(raw, plain); err != nil {
			return Backup{}, err
		}
	}
	if _, err := storage.CheckFile(ctx, plain); err != nil {
		return Backup{}, err
	}
	if err := gzipFile(plain, filepath.Join(m.dir, name)); err != nil {
		return Backup{}, err
	}
	b, _ := parse(name)
	if info, err := os.Stat(filepath.Join(m.dir, name)); err == nil {
		b.Size = info.Size()
	}
	m.log.Info("backup uploaded", "name", name, "bytes", b.Size)
	return b, nil
}

func isGzip(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	_, err = io.ReadFull(f, magic[:])
	return err == nil && magic[0] == 0x1f && magic[1] == 0x8b
}

// PendingPath is where a restore waits for the next start.
func PendingPath(dbPath string) string { return dbPath + ".restore" }

// StageRestore checks a backup, backs up the current database, and leaves
// the backup unpacked for ApplyPendingRestore on the next start.
func (m *Manager) StageRestore(ctx context.Context, name string) (Backup, error) {
	src, err := m.path(name)
	if err != nil {
		return Backup{}, err
	}
	if !m.jobMu.TryLock() {
		return Backup{}, ErrBusy
	}
	defer m.jobMu.Unlock()
	pending := PendingPath(m.db.Path())
	tmp := pending + ".partial"
	defer os.Remove(tmp)
	if err := gunzipFile(src, tmp); err != nil {
		return Backup{}, err
	}
	if _, err := storage.CheckFile(ctx, tmp); err != nil {
		return Backup{}, err
	}
	safety, err := m.create(ctx, BeforeRestore)
	if err != nil {
		return Backup{}, fmt.Errorf("couldn't back up the current database first, so nothing was changed: %w", err)
	}
	if err := os.Rename(tmp, pending); err != nil {
		return Backup{}, err
	}
	// A note for the next start, so it can record what was restored.
	note, _ := json.Marshal(RestoreInfo{Backup: name, SavedAs: safety.Name})
	_ = os.WriteFile(pending+".json", note, 0o600)
	m.log.Warn("restore staged; SIEMLite will restart to apply it", "backup", name, "current_saved_as", safety.Name)
	return safety, nil
}

// RestoreInfo describes an applied restore.
type RestoreInfo struct {
	Backup  string `json:"backup"`   // the backup restored
	SavedAs string `json:"saved_as"` // the database before it, as a backup
}

// ApplyPendingRestore swaps a staged restore into place. Call it before
// opening the database. It returns what was restored, or nil if nothing.
func ApplyPendingRestore(dbPath string, log *slog.Logger) (*RestoreInfo, error) {
	pending := PendingPath(dbPath)
	if !fileExists(pending) {
		return nil, nil
	}
	info := &RestoreInfo{}
	if b, err := os.ReadFile(pending + ".json"); err == nil {
		_ = json.Unmarshal(b, info)
	}
	defer os.Remove(pending + ".json")
	if log == nil {
		log = slog.Default()
	}
	if _, err := storage.CheckFile(context.Background(), pending); err != nil {
		bad := pending + ".rejected"
		_ = os.Rename(pending, bad)
		return nil, fmt.Errorf("the staged restore failed its check and was set aside as %s: %w", bad, err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	if err := os.Rename(pending, dbPath); err != nil {
		return nil, fmt.Errorf("apply restore: %w", err)
	}
	log.Warn("restored the database from a backup", "db", dbPath, "backup", info.Backup)
	return info, nil
}

// Settings returns the schedule.
func (m *Manager) Settings(ctx context.Context) (Settings, error) {
	iv, err := m.store.Setting(ctx, keyInterval, "0")
	if err != nil {
		return Settings{}, err
	}
	kp, err := m.store.Setting(ctx, keyKeep, "7")
	if err != nil {
		return Settings{}, err
	}
	s := Settings{}
	s.IntervalHours, _ = strconv.Atoi(iv)
	s.Keep, _ = strconv.Atoi(kp)
	if s.Keep < 1 {
		s.Keep = 7
	}
	return s, nil
}

// SetSettings saves the schedule.
func (m *Manager) SetSettings(ctx context.Context, s Settings) error {
	switch s.IntervalHours {
	case 0, 6, 24, 168:
	default:
		return errors.New("automatic backups run every 6 hours, every day, every week, or not at all")
	}
	if s.Keep < 1 || s.Keep > 365 {
		return errors.New("keep between 1 and 365 automatic backups")
	}
	if err := m.store.SetSetting(ctx, keyInterval, strconv.Itoa(s.IntervalHours)); err != nil {
		return err
	}
	return m.store.SetSetting(ctx, keyKeep, strconv.Itoa(s.Keep))
}

// prune deletes the oldest automatic backups beyond the number to keep.
// Other kinds are only ever deleted by hand.
func (m *Manager) prune(ctx context.Context) {
	s, err := m.Settings(ctx)
	if err != nil {
		return
	}
	list, err := m.List()
	if err != nil {
		return
	}
	kept := 0
	for _, b := range list {
		if b.Kind != Automatic {
			continue
		}
		kept++
		if kept > s.Keep {
			if err := os.Remove(filepath.Join(m.dir, b.Name)); err == nil {
				m.log.Info("old automatic backup removed", "name", b.Name)
			}
		}
	}
}

// Due reports whether an automatic backup should run now.
func (m *Manager) Due(ctx context.Context) bool {
	s, err := m.Settings(ctx)
	if err != nil || s.IntervalHours == 0 {
		return false
	}
	list, err := m.List()
	if err != nil {
		return false
	}
	for _, b := range list {
		if b.Kind == Automatic {
			return m.now().Sub(time.UnixMilli(b.CreatedAt)) >= time.Duration(s.IntervalHours)*time.Hour
		}
	}
	return true
}

// Run makes automatic backups on schedule until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if m.Due(ctx) {
			if err := m.Start(Automatic); err != nil && !errors.Is(err, ErrBusy) {
				m.log.Error("automatic backup failed to start", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Free returns the free bytes on the backups folder's file system.
func (m *Manager) Free() int64 { return freeBytes(m.dir) }

// CleanTemp removes partial files left by an interrupted backup.
func (m *Manager) CleanTemp() {
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, ".") || strings.HasSuffix(n, ".partial") {
			os.Remove(filepath.Join(m.dir, n))
		}
	}
}
