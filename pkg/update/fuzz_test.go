package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

const fuzzBin = "siemlite"

type entry struct {
	name string
	kind byte // 0 file, 1 symlink, 2 directory, 3 hard link, 4 file with a read-only mode
	data string
}

func buildTarGz(es []entry) ([]byte, bool) {
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.data)), Typeflag: tar.TypeReg}
		switch e.kind % 5 {
		case 1:
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, "/etc/passwd", 0
		case 2:
			h.Typeflag, h.Size = tar.TypeDir, 0
		case 3:
			h.Typeflag, h.Linkname, h.Size = tar.TypeLink, fuzzBin, 0
		case 4:
			h.Mode = 0o400
		}
		if tw.WriteHeader(h) != nil { // a name the format can't carry
			return nil, false
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				return nil, false
			}
		}
	}
	if tw.Close() != nil || gz.Close() != nil {
		return nil, false
	}
	return raw.Bytes(), true
}

func buildZip(es []entry) ([]byte, bool) {
	var raw bytes.Buffer
	zw := zip.NewWriter(&raw)
	for _, e := range es {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		switch e.kind % 5 {
		case 1:
			h.SetMode(0o777 | os.ModeSymlink)
		case 2:
			h.SetMode(0o755 | os.ModeDir)
		default:
			h.SetMode(0o755)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, false
		}
		if _, err := w.Write([]byte(e.data)); err != nil {
			return nil, false
		}
	}
	if zw.Close() != nil {
		return nil, false
	}
	return raw.Bytes(), true
}

// run extracts raw in a fresh directory of its own and returns what was written to dst, checking
// that nothing was written to disk, next to the archive or anywhere under its directory.
func run(t *testing.T, raw []byte, ext string) ([]byte, error) {
	t.Helper()
	dir := t.TempDir()
	parent := filepath.Dir(dir)
	before, _ := os.ReadDir(parent)
	path := filepath.Join(dir, "archive")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var out bytes.Buffer
	err = extract(fh, ext, fuzzBin, &out)
	if after, _ := os.ReadDir(dir); len(after) != 1 {
		t.Fatalf("extract left files behind: %v", after)
	}
	if after, _ := os.ReadDir(parent); len(after) != len(before) {
		t.Fatalf("extract wrote outside its directory: %d entries became %d", len(before), len(after))
	}
	return out.Bytes(), err
}

// FuzzExtractEntries builds archives from arbitrary entry names, kinds and contents. extract only
// ever copies the program out through the writer it is given: nothing is created on disk,
// whatever the names (../, absolute, backslashes, links), and the bytes it returns are those of a
// regular file called siemlite, never of a link or directory.
func FuzzExtractEntries(f *testing.F) {
	f.Add("siemlite-v1.2/siemlite", byte(0), "BIN1", "README.md", byte(0), "docs", "LICENSE", byte(0), "mit")
	f.Add("../../../etc/siemlite", byte(0), "TRAVERSAL", "/abs/siemlite", byte(0), "ABS", "..\\..\\siemlite", byte(0), "BACKSLASH")
	f.Add("siemlite", byte(1), "SYMLINK", "siemlite", byte(3), "HARDLINK", "bin/siemlite/", byte(2), "DIR")
	f.Add("a/b/../siemlite", byte(4), "READONLY", "siemlite\x00evil", byte(0), "NUL", "./siemlite", byte(0), "DOT")
	f.Add("", byte(0), "", ".", byte(0), "", "..", byte(2), "")
	f.Add("C:\\Windows\\siemlite", byte(0), "WIN", "\u202esiemlite", byte(0), "RLO", "siemlite.exe", byte(0), "EXE")
	f.Add("siemlite", byte(0), "", "siemlite", byte(0), "second", "x/siemlite", byte(0), "third")
	f.Fuzz(func(t *testing.T, n1 string, k1 byte, d1 string, n2 string, k2 byte, d2 string, n3 string, k3 byte, d3 string) {
		es := []entry{{n1, k1, d1}, {n2, k2, d2}, {n3, k3, d3}}
		// The first regular file whose base name matches is the one wanted. (A zip has no hard
		// links, so kind 3 is a plain file there.)
		pick := func(nonRegular ...byte) (string, bool) {
			for _, e := range es {
				reg := true
				for _, k := range nonRegular {
					reg = reg && e.kind%5 != k
				}
				if reg && filepath.Base(e.name) == fuzzBin && !hasSuffixSlash(e.name) {
					return e.data, true
				}
			}
			return "", false
		}
		want, found := pick(1, 2, 3)
		if raw, ok := buildTarGz(es); ok {
			got, err := run(t, raw, ".tar.gz")
			switch {
			case err == nil && !found:
				t.Fatalf("tar: copied %q though no regular %s is in it (%+v)", got, fuzzBin, es)
			case err == nil && string(got) != want:
				t.Fatalf("tar: got %q want %q (%+v)", got, want, es)
			case err != nil && found:
				t.Fatalf("tar: %v (%+v)", err, es)
			}
		}
		if raw, ok := buildZip(es); ok {
			zwant, zfound := pick(1, 2)
			got, err := run(t, raw, ".zip")
			if err == nil && (!zfound || string(got) != zwant) {
				t.Fatalf("zip: got %q (found=%v want %q) for %+v", got, zfound, zwant, es)
			}
		}
	})
}

func hasSuffixSlash(s string) bool { return len(s) > 0 && s[len(s)-1] == '/' }

// FuzzExtractBytes feeds extract arbitrary bytes as a download: it fails cleanly or copies bytes
// out, and never touches the disk.
func FuzzExtractBytes(f *testing.F) {
	tgz, _ := buildTarGz([]entry{{"siemlite-v1/siemlite", 0, "BINARY"}, {"siemlite-v1/README", 0, "hi"}})
	zp, _ := buildZip([]entry{{"siemlite-v1/siemlite", 0, "BINARY"}})
	f.Add(tgz, false)
	f.Add(zp, true)
	f.Add(tgz[:len(tgz)/2], false)
	f.Add(zp[:len(zp)-10], true)
	f.Add([]byte("\x1f\x8b\x08\x00"), false)
	f.Add([]byte("PK\x05\x06"+string(make([]byte, 18))), true)
	f.Add([]byte{}, true)
	f.Add(bytes.Repeat([]byte("ustar"), 300), false)
	f.Fuzz(func(t *testing.T, raw []byte, isZip bool) {
		ext := ".tar.gz"
		if isZip {
			ext = ".zip"
		}
		got, err := run(t, raw, ext)
		if err != nil && len(got) > maxBinary {
			t.Fatalf("copied %d bytes", len(got))
		}
	})
}
