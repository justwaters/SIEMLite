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

	c = fakeRelease(t, "v0.10", "new", false)
	c.InContainer = func() bool { return true }
	if st := c.Check(context.Background(), false); st.CanApply || !strings.Contains(st.WhyNot, "docker compose") {
		t.Errorf("container: %+v", st)
	}
	if _, err := c.Apply(context.Background()); err == nil {
		t.Error("applied inside a container")
	}
}

func TestCheckFailureIsReported(t *testing.T) {
	c := New("v0.9", "")
	c.API = "http://127.0.0.1:1/none"
	if st := c.Check(context.Background(), true); st.Error == "" || st.Available {
		t.Errorf("status = %+v", st)
	}
}
