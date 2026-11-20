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

// A release tag: v0.33, or a beta such as v0.34-beta.1.
var tagRe = regexp.MustCompile(`^v\d+(\.\d+)*(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

// The two release channels. Stable is every release not marked as a pre-release on GitHub; Beta
// also takes the pre-releases, so it gets a new version first.
const (
	Stable = "stable"
	Beta   = "beta"
)

// ChannelKey is the setting that holds the chosen channel.
const ChannelKey = "update_channel"

// ValidChannel reports whether ch is a channel name.
func ValidChannel(ch string) bool { return ch == Stable || ch == Beta }

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
	// Channel is the release channel being followed, and Prerelease whether Latest is a pre-release.
	Channel    string `json:"channel"`
	Prerelease bool   `json:"prerelease,omitempty"`
	// InContainer is set when SIEMLite runs in a container, where an update is
	// kept in the data volume instead of replacing the program file.
	InContainer bool `json:"in_container,omitempty"`
}

// Checker looks for releases and installs them.
type Checker struct {
	Current   string // e.g. "v0.9"
	Exe       string // the running binary, resolved when SIEMLite started
	DataDir   string // the folder holding the database; in a container updates are saved under it
	API       string // the "latest release" endpoint (Stable)
	ListAPI   string // the list of releases, pre-releases included (Beta); derived from API when empty
	Downloads string
	Client    *http.Client
	// InContainer overrides container detection (for tests).
	InContainer func() bool

	mu      sync.Mutex
	channel string
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
	st := Status{Current: c.Current, CheckedAt: time.Now(), Channel: c.channelLocked()}
	rel, err := c.fetchLatest(ctx, st.Channel)
	switch {
	case err != nil:
		st.Error = "Couldn't check for updates: " + err.Error()
		if c.cached.Latest != "" { // keep what we knew
			st.Latest, st.URL, st.Notes, st.Prerelease = c.cached.Latest, c.cached.URL, c.cached.Notes, c.cached.Prerelease
			st.Available = c.cached.Available
		}
	default:
		st.Latest, st.URL, st.Notes, st.Prerelease = rel.Tag, rel.URL, rel.Notes, rel.Pre
		st.Available = Newer(rel.Tag, c.Current)
	}
	c.cached, c.checked = st, time.Now()
	return c.withApply(st)
}

func (c *Checker) channelLocked() string {
	if c.channel == Beta {
		return Beta
	}
	return Stable
}

// Channel is the release channel being followed.
func (c *Checker) Channel() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.channelLocked()
}

// SetChannel changes the release channel; the next check looks there. Anything but Beta is Stable.
func (c *Checker) SetChannel(ch string) {
	if ch != Beta {
		ch = Stable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.channel != ch {
		c.channel = ch
		c.checked = time.Time{} // the answer for the other channel is not this one's
	}
}

func (c *Checker) withApply(st Status) Status {
	st.CanApply, st.WhyNot = c.canApply()
	st.InContainer = c.inContainer()
	return st
}

type release struct {
	Tag, URL, Notes string
	Pre             bool
}

type ghRelease struct {
	Tag   string `json:"tag_name"`
	URL   string `json:"html_url"`
	Body  string `json:"body"`
	Draft bool   `json:"draft"`
	Pre   bool   `json:"prerelease"`
}

func (g ghRelease) release() release {
	notes := g.Body
	if len(notes) > maxNotesSize {
		notes = notes[:maxNotesSize] + "…"
	}
	return release{g.Tag, g.URL, notes, g.Pre}
}

func (c *Checker) listURL() string {
	if c.ListAPI != "" {
		return c.ListAPI
	}
	return strings.TrimSuffix(c.API, "/latest") + "?per_page=30"
}

func (c *Checker) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SIEMLite/"+c.Current)
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub answered %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

// fetchLatest finds the newest release on a channel: Stable is what GitHub calls the latest
// release; Beta is the newest of all the published releases, pre-releases included.
func (c *Checker) fetchLatest(ctx context.Context, channel string) (release, error) {
	if channel == Beta {
		var list []ghRelease
		if err := c.getJSON(ctx, c.listURL(), &list); err != nil {
			return release{}, err
		}
		var best *ghRelease
		for i := range list {
			g := &list[i]
			if g.Draft || !tagRe.MatchString(g.Tag) {
				continue
			}
			if best == nil || Newer(g.Tag, best.Tag) {
				best = g
			}
		}
		if best == nil {
			return release{}, errors.New("GitHub lists no releases")
		}
		return best.release(), nil
	}
	var g ghRelease
	if err := c.getJSON(ctx, c.API, &g); err != nil {
		return release{}, err
	}
	if !tagRe.MatchString(g.Tag) {
		return release{}, fmt.Errorf("unexpected release name %q", g.Tag)
	}
	return g.release(), nil
}

// Newer reports whether release a is newer than b ("v0.10" > "v0.9"). A beta is older than the
// release it leads up to ("v0.34-beta.2" < "v0.34") and newer than an earlier beta; a version that
// isn't a release number (a development build) is never older.
func Newer(a, b string) bool {
	if !tagRe.MatchString(a) || !tagRe.MatchString(b) {
		return false
	}
	na, pa := splitPre(a)
	nb, pb := splitPre(b)
	x, y := parts(na), parts(nb)
	for i := 0; i < len(x) || i < len(y); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			return p > q
		}
	}
	switch {
	case pa == pb:
		return false
	case pa == "":
		return true // a is the release itself
	case pb == "":
		return false
	}
	ia, ib := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < len(ia) && i < len(ib); i++ {
		if ia[i] == ib[i] {
			continue
		}
		na, ea := strconv.Atoi(ia[i])
		nb, eb := strconv.Atoi(ib[i])
		switch {
		case ea == nil && eb == nil:
			return na > nb
		case ea == nil:
			return false // a number is older than a word
		case eb == nil:
			return true
		}
		return ia[i] > ib[i]
	}
	return len(ia) > len(ib)
}

func splitPre(v string) (num, pre string) {
	num, pre, _ = strings.Cut(v, "-")
	return num, pre
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

// target is where an update is written: the program file itself, or in a
// container (whose program file is part of the image) a copy in the data
// volume that the image's program hands over to when it starts.
func (c *Checker) target() string {
	if c.inContainer() {
		return OverridePath(c.DataDir)
	}
	return c.Exe
}

const containerAdvice = "update it from the SIEMLite folder on the server with ./update.sh (or docker compose pull && docker compose up -d)"

// canApply says whether this install can update itself.
func (c *Checker) canApply() (bool, string) {
	if c.inContainer() {
		if c.DataDir == "" {
			return false, "SIEMLite is running in a container with no data folder to save an update in, so " + containerAdvice
		}
		if !writable(filepath.Dir(OverridePath(c.DataDir))) {
			return false, "SIEMLite can't write to its data folder " + c.DataDir + ", so " + containerAdvice
		}
		return true, ""
	}
	if c.Exe == "" {
		return false, "SIEMLite can't tell where its program file is"
	}
	if !writable(filepath.Dir(c.Exe)) {
		return false, "SIEMLite can't write to " + filepath.Dir(c.Exe) + ", so download the new release and replace the program yourself"
	}
	return true, ""
}

// writable reports whether files can be created in dir, making it if needed.
func writable(dir string) bool {
	if os.MkdirAll(dir, 0o755) != nil {
		return false
	}
	probe, err := os.CreateTemp(dir, ".siemlite-write-test-*")
	if err != nil {
		return false
	}
	probe.Close()
	os.Remove(probe.Name())
	return true
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

	dir := filepath.Dir(c.target())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
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
	if c.inContainer() {
		return saveOverride(c.DataDir, next.Name(), tag)
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
