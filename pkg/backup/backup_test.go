package backup

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

type env struct {
	t    *testing.T
	dir  string
	path string
	db   *storage.DB
	repo *storage.Repository
	m    *Manager
	now  time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	e.path = filepath.Join(e.dir, "siemlite.db")
	e.open()
	return e
}

func (e *env) open() {
	e.t.Helper()
	db, err := storage.Open(context.Background(), storage.Options{Path: e.path})
	if err != nil {
		e.t.Fatal(err)
	}
	e.db, e.repo = db, storage.NewRepository(db)
	m, err := New(filepath.Join(e.dir, "backups"), db, e.repo, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	m.now = func() time.Time { return e.now }
	e.m = m
}

func (e *env) addEvent(text string) {
	e.t.Helper()
	if err := e.repo.InsertBatch(context.Background(), []storage.Record{{Timestamp: 1, CategoryUID: 6, ClassUID: 6003, SeverityID: 1, RawData: text}}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) events() []string {
	recs, err := e.repo.Search(context.Background(), storage.Filter{Limit: 100})
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		out = append(out, r.RawData)
	}
	return out
}

func TestCreateRestoreRoundTrip(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addEvent("before")
	b, err := e.m.Create(ctx, Manual)
	if err != nil {
		t.Fatal(err)
	}
	if b.Kind != Manual || b.Size == 0 || !strings.HasSuffix(b.Name, "-manual.db.gz") {
		t.Errorf("backup = %+v", b)
	}
	e.addEvent("after")

	e.now = e.now.Add(time.Minute)
	safety, err := e.m.StageRestore(ctx, b.Name)
	if err != nil {
		t.Fatal(err)
	}
	if safety.Kind != BeforeRestore {
		t.Errorf("safety backup = %+v", safety)
	}
	// Nothing changes until the restart applies the restore.
	if got := e.events(); len(got) != 2 {
		t.Errorf("events before restart = %v", got)
	}
	e.db.Close()
	applied, err := ApplyPendingRestore(e.path, nil)
	if err != nil || applied == nil || applied.Backup != b.Name || applied.SavedAs != safety.Name {
		t.Fatalf("apply = %+v, %v", applied, err)
	}
	e.open()
	defer e.db.Close()
	if got := e.events(); len(got) != 1 || got[0] != "before" {
		t.Errorf("events after restore = %v", got)
	}
	// The safety backup still has both events: the restore can be undone.
	list, _ := e.m.List()
	if len(list) != 2 || list[0].Kind != BeforeRestore {
		t.Errorf("list = %+v", list)
	}
	if applied, _ := ApplyPendingRestore(e.path, nil); applied != nil {
		t.Error("restore applied twice")
	}
}

func TestUploadChecksFiles(t *testing.T) {
	e := newEnv(t)
	defer e.db.Close()
	ctx := context.Background()
	e.addEvent("x")
	b, _ := e.m.Create(ctx, Manual)
	f, _ := e.m.Open(b.Name)
	gz, _ := readAll(f)

	if up, err := e.m.Upload(ctx, bytes.NewReader(gz)); err != nil || up.Kind != Uploaded {
		t.Errorf("upload gzip backup = %+v, %v", up, err)
	}
	// A plain .db file is accepted too.
	plain := filepath.Join(e.dir, "plain.db")
	if err := e.db.SnapshotTo(ctx, plain); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(plain)
	e.now = e.now.Add(time.Second)
	if _, err := e.m.Upload(ctx, bytes.NewReader(raw)); err != nil {
		t.Errorf("upload plain db: %v", err)
	}
	if _, err := e.m.Upload(ctx, strings.NewReader("not a database at all")); err == nil {
		t.Error("junk accepted")
	}
	// A backup from a newer SIEMLite is refused.
	newer := filepath.Join(e.dir, "newer.db")
	_ = e.db.SnapshotTo(ctx, newer)
	nd, _ := sql.Open("sqlite", newer)
	nd.Exec(`PRAGMA user_version = 999`)
	nd.Close()
	raw, _ = os.ReadFile(newer)
	if _, err := e.m.Upload(ctx, bytes.NewReader(raw)); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("newer backup: %v", err)
	}
	list, _ := e.m.List()
	if len(list) != 3 {
		t.Errorf("rejected uploads left files: %+v", list)
	}
}

func TestNamesAndDelete(t *testing.T) {
	e := newEnv(t)
	defer e.db.Close()
	b, _ := e.m.Create(context.Background(), Manual)
	for _, bad := range []string{"../siemlite.db", "siemlite.db", "", "siemlite-20261003-120000-manual.db.gz/../../x"} {
		if err := e.m.Delete(bad); err != ErrNotFound {
			t.Errorf("Delete(%q) = %v", bad, err)
		}
	}
	// Two backups in the same second get distinct names.
	b2, _ := e.m.Create(context.Background(), Manual)
	if b2.Name == b.Name {
		t.Error("duplicate backup name")
	}
	if err := e.m.Delete(b.Name); err != nil {
		t.Fatal(err)
	}
	if list, _ := e.m.List(); len(list) != 1 {
		t.Errorf("after delete: %+v", list)
	}
}

func TestScheduleAndPrune(t *testing.T) {
	e := newEnv(t)
	defer e.db.Close()
	ctx := context.Background()
	if e.m.Due(ctx) {
		t.Error("due while automatic backups are off")
	}
	if err := e.m.SetSettings(ctx, Settings{IntervalHours: 5, Keep: 2}); err == nil {
		t.Error("odd interval accepted")
	}
	if err := e.m.SetSettings(ctx, Settings{IntervalHours: 24, Keep: 2}); err != nil {
		t.Fatal(err)
	}
	if !e.m.Due(ctx) {
		t.Error("not due with no automatic backups yet")
	}
	e.m.Create(ctx, Manual)
	for i := 0; i < 4; i++ {
		if _, err := e.m.Create(ctx, Automatic); err != nil {
			t.Fatal(err)
		}
		if e.m.Due(ctx) {
			t.Errorf("due right after a backup")
		}
		e.now = e.now.Add(25 * time.Hour)
		if !e.m.Due(ctx) {
			t.Errorf("not due a day later")
		}
	}
	list, _ := e.m.List()
	auto, manual := 0, 0
	for _, b := range list {
		switch b.Kind {
		case Automatic:
			auto++
		case Manual:
			manual++
		}
	}
	if auto != 2 || manual != 1 {
		t.Errorf("after pruning: %d automatic, %d manual (want 2, 1)", auto, manual)
	}
}

func readAll(f *os.File) ([]byte, error) {
	defer f.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(f)
	return buf.Bytes(), err
}
