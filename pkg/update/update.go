// Package update checks GitHub for a newer SIEMLite release and, for installs
// that run a plain binary, replaces the binary with it.
package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAPI is the "latest release" endpoint; DefaultDownloads is where release assets live.
	DefaultAPI       = "https://api.github.com/repos/justwaters/SIEMLite/releases/latest"
	DefaultDownloads = "https://github.com/justwaters/SIEMLite/releases/download"

	cacheFor     = 6 * time.Hour
	maxArchive   = 256 << 20
	maxBinary    = 256 << 20
	maxNotesSize = 4000
)

var tagRe = regexp.MustCompile(`^v\d+(\.\d+)*$`)

// ErrNotAvailable means there is no newer release to install.
var ErrNotAvailable = errors.New("SIEMLite is already up to date")

// Status is what the System page shows.
type Status struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	Available bool      `json:"available"`
	URL       string    `json:"url,omitempty"` // the release page
	Notes     string    `json:"notes,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Error     string    `json:"error,omitempty"`
	// CanApply is whether the update button works here; if not, WhyNot says
	// what to do instead.
	CanApply bool   `json:"can_apply"`
	WhyNot   string `json:"why_not,omitempty"`
}

// Checker looks for releases and installs them.
type Checker struct {
	Current   string // e.g. "v0.9"
	Exe       string // the running binary, resolved when SIEMLite started
	API       string
	Downloads string
	Client    *http.Client
	// InContainer overrides container detection (for tests).
	InContainer func() bool

	mu      sync.Mutex
	cached  Status
	checked time.Time
	busy    bool
}

// New returns a Checker for the running binary exe.
func New(current, exe string) *Checker {
	return &Checker{Current: current, Exe: exe, API: DefaultAPI, Downloads: DefaultDownloads,
		Client: &http.Client{Timeout: 15 * time.Second}}
}

// Check returns the update status. Results are cached for a few hours unless
// force is set; a failed check is reported in Status.Error, not as an error.
func (c *Checker) Check(ctx context.Context, force bool) Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && !c.checked.IsZero() && time.Since(c.checked) < cacheFor && c.cached.Error == "" {
		return c.withApply(c.cached)
	}
	st := Status{Current: c.Current, CheckedAt: time.Now()}
	rel, err := c.fetchLatest(ctx)
	switch {
	case err != nil:
		st.Error = "Couldn't check for updates: " + err.Error()
		if c.cached.Latest != "" { // keep what we knew
			st.Latest, st.URL, st.Notes = c.cached.Latest, c.cached.URL, c.cached.Notes
			st.Available = c.cached.Available
		}
	default:
		st.Latest, st.URL, st.Notes = rel.Tag, rel.URL, rel.Notes
		st.Available = Newer(rel.Tag, c.Current)
	}
	c.cached, c.checked = st, time.Now()
	return c.withApply(st)
}

func (c *Checker) withApply(st Status) Status {
	st.CanApply, st.WhyNot = c.canApply()
	return st
}

type release struct{ Tag, URL, Notes string }

func (c *Checker) fetchLatest(ctx context.Context) (release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.API, nil)
	if err != nil {
		return release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SIEMLite/"+c.Current)
	resp, err := c.Client.Do(req)
	if err != nil {
		return release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return release{}, fmt.Errorf("GitHub answered %s", resp.Status)
	}
	var body struct {
		Tag  string `json:"tag_name"`
		URL  string `json:"html_url"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return release{}, err
	}
	if !tagRe.MatchString(body.Tag) {
		return release{}, fmt.Errorf("unexpected release name %q", body.Tag)
	}
	notes := body.Body
	if len(notes) > maxNotesSize {
		notes = notes[:maxNotesSize] + "…"
	}
	return release{body.Tag, body.URL, notes}, nil
}

// Newer reports whether release a is newer than b ("v0.10" > "v0.9"). A
// version that isn't a release number (a development build) is never older.
func Newer(a, b string) bool {
	if !tagRe.MatchString(a) || !tagRe.MatchString(b) {
		return false
	}
	pa, pb := parts(a), parts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func parts(v string) []int {
	var out []int
	for _, p := range strings.Split(strings.TrimPrefix(v, "v"), ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

func (c *Checker) inContainer() bool {
	if c.InContainer != nil {
		return c.InContainer()
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// canApply says whether this install can replace its own binary.
func (c *Checker) canApply() (bool, string) {
	if c.inContainer() {
		return false, "SIEMLite is running in a container, so update by pulling the new image: docker compose pull && docker compose up -d"
	}
	if c.Exe == "" {
		return false, "SIEMLite can't tell where its program file is"
	}
	probe, err := os.CreateTemp(filepath.Dir(c.Exe), ".siemlite-write-test-*")
	if err != nil {
		return false, "SIEMLite can't write to " + filepath.Dir(c.Exe) + ", so download the new release and replace the program yourself"
	}
	probe.Close()
	os.Remove(probe.Name())
	return true, ""
}

// Apply downloads the latest release, checks it against the release's
// SHA256SUMS, and swaps it in for the running binary. The caller restarts
// SIEMLite afterwards. It returns the version installed.
func (c *Checker) Apply(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.busy {
		c.mu.Unlock()
		return "", errors.New("an update is already in progress")
	}
	c.busy = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.busy = false; c.mu.Unlock() }()

	if ok, why := c.canApply(); !ok {
		return "", errors.New(why)
	}
	st := c.Check(ctx, true)
	if st.Error != "" {
		return "", errors.New(st.Error)
	}
	if !st.Available {
		return "", ErrNotAvailable
	}
	if err := c.install(ctx, st.Latest); err != nil {
		return "", err
	}
	return st.Latest, nil
}

func (c *Checker) install(ctx context.Context, tag string) error {
	if !tagRe.MatchString(tag) {
		return fmt.Errorf("unexpected release name %q", tag)
	}
	ext, binName := ".tar.gz", "siemlite"
	if runtime.GOOS == "windows" {
		ext, binName = ".zip", "siemlite.exe"
	}
	asset := fmt.Sprintf("siemlite-%s-%s-%s%s", tag, runtime.GOOS, runtime.GOARCH, ext)
	base := strings.TrimRight(c.Downloads, "/") + "/" + tag + "/"

	sums, err := c.fetchText(ctx, base+"SHA256SUMS")
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	want := checksumFor(sums, asset)
	if want == "" {
		return fmt.Errorf("release %s has no build for %s/%s", tag, runtime.GOOS, runtime.GOARCH)
	}

	dir := filepath.Dir(c.Exe)
	archive, err := os.CreateTemp(dir, ".siemlite-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(archive.Name())
	defer archive.Close()
	got, err := c.download(ctx, base+asset, archive)
	if err != nil {
		return fmt.Errorf("download %s: %w", asset, err)
	}
	if got != want {
		return fmt.Errorf("download of %s is corrupt (checksum mismatch); nothing was changed", asset)
	}

	next, err := os.CreateTemp(dir, ".siemlite-new-*")
	if err != nil {
		return err
	}
	defer os.Remove(next.Name()) // gone already once renamed into place
	err = extract(archive, ext, binName, next)
	next.Close()
	if err != nil {
		return err
	}
	if err := os.Chmod(next.Name(), 0o755); err != nil {
		return err
	}
	return swap(c.Exe, next.Name())
}

func (c *Checker) fetchText(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "SIEMLite/"+c.Current)
	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), err
}

// download streams url into f and returns its SHA-256.
func (c *Checker) download(ctx context.Context, url string, f *os.File) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "SIEMLite/"+c.Current)
	// The shared client's timeout is for small requests.
	resp, err := (&http.Client{Timeout: 10 * time.Minute, Transport: c.Client.Transport}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return "", err
	}
	if n > maxArchive {
		return "", errors.New("file is unexpectedly large")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checksumFor finds asset's hash in a sha256sum listing.
func checksumFor(sums, asset string) string {
	sc := bufio.NewScanner(strings.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// extract copies the program file called binName out of the archive into dst.
func extract(archive *os.File, ext, binName string, dst io.Writer) error {
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	copyBin := func(r io.Reader) error {
		n, err := io.Copy(dst, io.LimitReader(r, maxBinary+1))
		if err == nil && n > maxBinary {
			err = errors.New("program is unexpectedly large")
		}
		return err
	}
	if ext == ".zip" {
		info, err := archive.Stat()
		if err != nil {
			return err
		}
		zr, err := zip.NewReader(archive, info.Size())
		if err != nil {
			return err
		}
		for _, f := range zr.File {
			if f.FileInfo().Mode().IsRegular() && filepath.Base(f.Name) == binName {
				rc, err := f.Open()
				if err != nil {
					return err
				}
				defer rc.Close()
				return copyBin(rc)
			}
		}
		return errors.New("the download doesn't contain " + binName)
	}
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("the download doesn't contain " + binName)
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == binName {
			return copyBin(tr)
		}
	}
}

// swap puts the new program at exe, keeping the old one as exe.old until the
// swap has worked. Renaming over a running program is fine on Unix, and
// renaming it aside first is what lets Windows do the same.
func swap(exe, next string) error {
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(next, exe); err != nil {
		_ = os.Rename(old, exe)
		return err
	}
	os.Remove(old) // can fail on Windows while it runs; removed on the next update
	return nil
}
