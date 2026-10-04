package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"

	"siemlite/pkg/storage"
)

// A backup is a gzipped tar of a snapshot folder: the main database as
// storage.MainFile and each day as events/YYYY-MM-DD.db. Backups from before
// day files are a single gzipped database; they still restore (their events
// are then moved into day files on start).

var entryRe = regexp.MustCompile(`^` + regexp.QuoteMeta(storage.EventsFolder) + `/\d{4}-\d{2}-\d{2}\.db$`)

// writeArchive packs a snapshot folder into dst, writing to a temporary name
// first so a half-written backup never appears in the list.
func writeArchive(dir, dst string) error {
	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw, _ := gzip.NewWriterLevel(out, gzip.BestSpeed)
	tw := tar.NewWriter(zw)
	err = addFile(tw, filepath.Join(dir, storage.MainFile), storage.MainFile)
	if err == nil {
		var days []os.DirEntry
		days, err = os.ReadDir(filepath.Join(dir, storage.EventsFolder))
		for _, e := range days {
			if err != nil {
				break
			}
			name := path.Join(storage.EventsFolder, e.Name())
			if entryRe.MatchString(name) {
				err = addFile(tw, filepath.Join(dir, storage.EventsFolder, e.Name()), name)
			}
		}
	}
	if err == nil {
		err = tw.Close()
	}
	if err == nil {
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

func addFile(tw *tar.Writer, src, name string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), ModTime: fi.ModTime(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// unpack extracts a backup (either format) into dir, which must not exist,
// and checks every database in it. Only the expected names are accepted, so
// nothing in an archive can be written anywhere else.
func unpack(ctx context.Context, src, dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, storage.EventsFolder), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	var r io.Reader = in
	if isGzip(src) {
		zr, err := gzip.NewReader(in)
		if err != nil {
			return fmt.Errorf("the backup isn't a gzip file: %w", err)
		}
		defer zr.Close()
		r = zr
	}
	// A tar archive, or (older backups and plain uploads) a database alone.
	br := newPeekReader(r)
	head, _ := br.peek(512)
	if !isTar(head) {
		if err := writeFile(filepath.Join(dir, storage.MainFile), br); err != nil {
			return fmt.Errorf("unpack backup: %w", err)
		}
	} else {
		tr := tar.NewReader(br)
		seen := map[string]bool{}
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Errorf("the backup is damaged: %w", err)
			}
			if h.Typeflag != tar.TypeReg || (h.Name != storage.MainFile && !entryRe.MatchString(h.Name)) || seen[h.Name] {
				return fmt.Errorf("the backup holds something unexpected: %q", h.Name)
			}
			seen[h.Name] = true
			if err := writeFile(filepath.Join(dir, filepath.FromSlash(h.Name)), tr); err != nil {
				return fmt.Errorf("unpack backup: %w", err)
			}
		}
		if !seen[storage.MainFile] {
			return errors.New("the backup has no main database")
		}
	}
	return check(ctx, dir)
}

// check verifies the main database and every day file in a snapshot folder.
func check(ctx context.Context, dir string) error {
	if _, err := storage.CheckFile(ctx, filepath.Join(dir, storage.MainFile)); err != nil {
		return err
	}
	days, err := os.ReadDir(filepath.Join(dir, storage.EventsFolder))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range days {
		if err := storage.CheckDayFile(ctx, filepath.Join(dir, storage.EventsFolder, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(dst string, r io.Reader) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, r)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// isTar reports whether a block starts a tar archive ("ustar" magic).
func isTar(head []byte) bool {
	return len(head) >= 262 && slices.Equal(head[257:262], []byte("ustar"))
}

// peekReader lets the first bytes be looked at and then read again.
type peekReader struct {
	r   io.Reader
	buf []byte
}

func newPeekReader(r io.Reader) *peekReader { return &peekReader{r: r} }

func (p *peekReader) peek(n int) ([]byte, error) {
	for len(p.buf) < n {
		chunk := make([]byte, n-len(p.buf))
		k, err := p.r.Read(chunk)
		p.buf = append(p.buf, chunk[:k]...)
		if err != nil {
			return p.buf, err
		}
	}
	return p.buf, nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}
