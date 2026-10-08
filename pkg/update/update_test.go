package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.10", "v0.9", true}, {"v0.9", "v0.10", false}, {"v0.9", "v0.9", false},
		{"v0.9.1", "v0.9", true}, {"v1.0", "v0.47.1", true}, {"v0.9", "dev", false}, {"v0.9", "", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// fakeRelease serves a fake GitHub with one release whose program says content.
func fakeRelease(t *testing.T, tag, content string, badSum bool) *Checker {
	t.Helper()
	ext, bin := ".tar.gz", "siemlite"
	var buf bytes.Buffer
	if runtime.GOOS == "windows" {
		ext, bin = ".zip", "siemlite.exe"
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create("pkg/" + bin)
		w.Write([]byte(content))
		zw.Close()
	} else {
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: "pkg/" + bin, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
		tw.Write([]byte(content))
		tw.Close()
		gz.Close()
	}
	asset := fmt.Sprintf("siemlite-%s-%s-%s%s", tag, runtime.GOOS, runtime.GOARCH, ext)
	sum := sha256.Sum256(buf.Bytes())
	hexSum := hex.EncodeToString(sum[:])
	if badSum {
		hexSum = strings.Repeat("0", 64)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":%q,"html_url":"https://example.test/r","body":"notes"}`, tag)
	})
	mux.HandleFunc("/dl/"+tag+"/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "%s  %s\n", hexSum, asset) })
	mux.HandleFunc("/dl/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write(buf.Bytes()) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	exe := filepath.Join(t.TempDir(), bin)
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := New("v0.9", exe)
	c.API, c.Downloads, c.InContainer = srv.URL+"/latest", srv.URL+"/dl", func() bool { return false }
	return c
}

func TestCheckAndApply(t *testing.T) {
	c := fakeRelease(t, "v0.10", "new program", false)
	st := c.Check(context.Background(), false)
	if !st.Available || st.Latest != "v0.10" || st.Error != "" || !st.CanApply || st.Notes != "notes" {
		t.Fatalf("status = %+v", st)
	}
	got, err := c.Apply(context.Background())
	if err != nil || got != "v0.10" {
		t.Fatalf("Apply = %q, %v", got, err)
	}
	if b, _ := os.ReadFile(c.Exe); string(b) != "new program" {
		t.Errorf("program is %q", b)
	}
	if _, err := os.Stat(c.Exe + ".old"); err == nil && runtime.GOOS != "windows" {
		t.Error("old program left behind")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(c.Exe), ".siemlite-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestApplyRefusals(t *testing.T) {
	c := fakeRelease(t, "v0.10", "new", true)
	if _, err := c.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("bad checksum: %v", err)
	}
	if b, _ := os.ReadFile(c.Exe); string(b) != "old" {
		t.Errorf("program changed to %q", b)
	}

	c = fakeRelease(t, "v0.9", "same", false)
	if _, err := c.Apply(context.Background()); err != ErrNotAvailable {
		t.Errorf("up to date: %v", err)
	}

	// In a container with no data folder there is nowhere to save an update.
	c = fakeRelease(t, "v0.10", "new", false)
	c.InContainer = func() bool { return true }
	if st := c.Check(context.Background(), false); st.CanApply || !strings.Contains(st.WhyNot, "docker compose") || !st.InContainer {
		t.Errorf("container without a data folder: %+v", st)
	}
	if _, err := c.Apply(context.Background()); err == nil {
		t.Error("applied inside a container with no data folder")
	}
}

func TestContainerUpdateIsSavedInTheDataFolder(t *testing.T) {
	c := fakeRelease(t, "v0.10", "new program", false)
	c.InContainer = func() bool { return true }
	c.DataDir = t.TempDir()
	if st := c.Check(context.Background(), false); !st.CanApply || !st.InContainer {
		t.Fatalf("status = %+v", st)
	}
	if got, err := c.Apply(context.Background()); err != nil || got != "v0.10" {
		t.Fatalf("Apply = %q, %v", got, err)
	}
	if b, _ := os.ReadFile(c.Exe); string(b) != "old" {
		t.Errorf("the image's program was changed to %q", b)
	}
	if b, _ := os.ReadFile(OverridePath(c.DataDir)); string(b) != "new program" {
		t.Errorf("saved program is %q", b)
	}
	if fi, err := os.Stat(OverridePath(c.DataDir)); err != nil || fi.Mode()&0o111 == 0 {
		t.Errorf("saved program isn't executable: %v %v", fi, err)
	}

	// The image's program (v0.9) hands over, and a start that never comes up is counted.
	self := c.Exe
	if p, note := Override(c.DataDir, "v0.9", self); p != OverridePath(c.DataDir) || note != "" {
		t.Fatalf("first start: %q %q", p, note)
	}
	if p, _ := Override(c.DataDir, "v0.9", self); p == "" {
		t.Fatal("second start didn't hand over")
	}
	if p, note := Override(c.DataDir, "v0.9", self); p != "" || note == "" {
		t.Errorf("third start should drop the saved update: %q %q", p, note)
	}
	if _, err := os.Stat(OverridePath(c.DataDir)); err == nil {
		t.Error("the failed update was kept")
	}
}

func TestOverrideRules(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(t.TempDir(), "siemlite")
	os.WriteFile(self, []byte("image"), 0o755)
	if p, note := Override(dir, "v0.9", self); p != "" || note != "" {
		t.Errorf("nothing saved: %q %q", p, note)
	}
	save := func(tag string) {
		next := filepath.Join(dir, "next")
		os.WriteFile(next, []byte("saved"), 0o755)
		os.MkdirAll(binDir(dir), 0o755)
		if err := saveOverride(dir, next, tag); err != nil {
			t.Fatal(err)
		}
	}
	// A healthy start clears the attempts, so later restarts are never blocked.
	save("v0.10")
	for i := 0; i < 5; i++ {
		if p, _ := Override(dir, "v0.9", self); p == "" {
			t.Fatalf("restart %d didn't hand over", i)
		}
		MarkHealthy(dir)
	}
	// Running as the saved program itself never hands over or deletes itself.
	if p, note := Override(dir, "v0.10", OverridePath(dir)); p != "" || note != "" {
		t.Errorf("saved program running: %q %q", p, note)
	}
	if _, err := os.Stat(OverridePath(dir)); err != nil {
		t.Error("the running saved program was removed")
	}
	// Once the image catches up (rebuilt or pulled), the saved copy goes.
	if p, note := Override(dir, "v0.10", self); p != "" || note == "" {
		t.Errorf("image caught up: %q %q", p, note)
	}
	if _, err := os.Stat(binDir(dir)); err == nil {
		t.Error("stale saved update kept")
	}
	// An older saved update never overrides a newer image.
	save("v0.8")
	if p, _ := Override(dir, "v0.9", self); p != "" {
		t.Error("an older saved update took over")
	}
}

func TestCheckFailureIsReported(t *testing.T) {
	c := New("v0.9", "")
	c.API = "http://127.0.0.1:1/none"
	if st := c.Check(context.Background(), true); st.Error == "" || st.Available {
		t.Errorf("status = %+v", st)
	}
}
