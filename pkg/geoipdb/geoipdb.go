// Package geoipdb downloads the free DB-IP "lite" City and ASN databases (CC BY 4.0, no
// account) so IP locations work with no setup, and keeps them current: DB-IP publishes a
// new edition each month, and Check looks for one at start and whenever updates are checked.
//
// Only downloads happen: nothing about your events is ever sent. A download is written to a
// temporary file next to the real one, opened and tried with a lookup, and only then renamed
// into place, so a broken or hostile download never replaces a working database.
package geoipdb

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Where the databases come from, and the credit DB-IP asks for.
const (
	DefaultBase = "https://download.db-ip.com/free/"
	Host        = "download.db-ip.com"
	Attribution = "IP geolocation data by DB-IP.com, licensed under CC BY 4.0"
)

// Settings kept in the settings store.
const (
	SettingEnabled = "geoip_enabled" // "0" or "1"; on when missing
	SettingState   = "geoip_state"   // JSON: when the last check ran and what it said
)

// Limits on what a download may use. The real files are about 5 MB (ASN) and 60 MB (City)
// compressed; these leave room to grow and stop a hostile or broken server filling the disk.
const (
	MaxCompressed   = 400 << 20
	MaxDecompressed = 1 << 30
	headerTimeout   = 30 * time.Second
	downloadTimeout = 15 * time.Minute
)

// Kind is one of the two databases.
type Kind string

// The two databases.
const (
	City Kind = "city"
	ASN  Kind = "asn"
)

var kinds = []Kind{City, ASN}

var nameRe = regexp.MustCompile(`^dbip-(city|asn)-lite-([0-9]{4}-(?:0[1-9]|1[0-2]))\.mmdb$`)

// ParseName reads the kind and edition ("2026-11") out of a stored file name such as
// dbip-city-lite-2026-11.mmdb.
func ParseName(name string) (Kind, string, bool) {
	m := nameRe.FindStringSubmatch(name)
	if m == nil {
		return "", "", false
	}
	return Kind(m[1]), m[2], true
}

// FileName is the stored file name of an edition.
func FileName(k Kind, edition string) string {
	return "dbip-" + string(k) + "-lite-" + edition + ".mmdb"
}

func remoteName(k Kind, edition string) string { return FileName(k, edition) + ".gz" }

// Store keeps the settings; storage.Repository satisfies it.
type Store interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Applier loads databases without a restart; enrich.GeoIP satisfies it. An empty path unloads.
type Applier interface {
	Swap(cityPath, asnPath string) error
}

// DBInfo describes one loaded database.
type DBInfo struct {
	Edition string `json:"edition"` // "2026-11", or empty when there is none
	Built   string `json:"built"`   // when DB-IP built it (RFC 3339), or empty
}

// Status is what the System page shows.
type Status struct {
	Enabled     bool   `json:"enabled"`
	Source      string `json:"source"` // "dbip", "own" (your files, given at start) or "none"
	City        DBInfo `json:"city"`
	ASN         DBInfo `json:"asn"`
	LastChecked int64  `json:"last_checked"` // unix ms, 0 = never
	LastError   string `json:"last_error"`
	Checking    bool   `json:"checking,omitempty"`
	Attribution string `json:"attribution"`
}

type persisted struct {
	LastChecked int64  `json:"last_checked"`
	LastError   string `json:"last_error"`
}

// Service downloads and loads the databases.
type Service struct {
	Dir    string // <data dir>/geoip
	Store  Store
	Target Applier
	Log    *slog.Logger
	// Own is set when the operator gave -geoip-city/-geoip-asn: those win and nothing is downloaded.
	Own bool
	// Base is the folder the files are under (default DefaultBase). Only for tests and the e2e.
	Base string
	// Client is used for downloads (default: timeouts of 30 s to connect and get headers). Its redirects are limited
	// to the host of Base either way.
	Client *http.Client
	Now    func() time.Time
	// Limits override MaxCompressed and MaxDecompressed (tests).
	MaxCompressed, MaxDecompressed int64

	checkMu  sync.Mutex // one check at a time
	checking atomic.Bool
	mu       sync.Mutex
	st       persisted
	info     map[Kind]DBInfo
	paths    map[Kind]string
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) base() (*url.URL, error) {
	b := s.Base
	if b == "" {
		b = DefaultBase
	}
	if !strings.HasSuffix(b, "/") {
		b += "/"
	}
	u, err := url.Parse(b)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the download address %q must be an https address", b)
	}
	return u, nil
}

// Enabled reports whether downloading is on (the default).
func (s *Service) Enabled(ctx context.Context) bool {
	v, err := s.Store.Setting(ctx, SettingEnabled, "")
	return err != nil || v != "0"
}

// Status describes the current state.
func (s *Service) Status(ctx context.Context) Status {
	enabled := s.Enabled(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Enabled: enabled, Source: "none", LastChecked: s.st.LastChecked, LastError: s.st.LastError,
		Checking: s.checking.Load(), Attribution: Attribution}
	switch {
	case s.Own:
		st.Source = "own"
	case enabled && (s.paths[City] != "" || s.paths[ASN] != ""):
		st.Source = "dbip"
		st.City, st.ASN = s.info[City], s.info[ASN]
	}
	return st
}

// Load starts from what is already on disk: the newest valid edition of each database. It
// never uses the network.
func (s *Service) Load(ctx context.Context) {
	s.checkMu.Lock()
	defer s.checkMu.Unlock()
	if raw, _ := s.Store.Setting(ctx, SettingState, ""); raw != "" {
		var p persisted
		if json.Unmarshal([]byte(raw), &p) == nil {
			s.mu.Lock()
			s.st = p
			s.mu.Unlock()
		}
	}
	if s.Own {
		return
	}
	s.cleanTemp()
	s.mu.Lock()
	s.info, s.paths = map[Kind]DBInfo{}, map[Kind]string{}
	s.mu.Unlock()
	for _, k := range kinds {
		if !s.Enabled(ctx) {
			break // off: nothing is loaded, though the files stay for turning it on again
		}
		for _, ed := range s.editions(k) { // newest first
			path := filepath.Join(s.Dir, FileName(k, ed))
			meta, err := Verify(path, k, s.now())
			if err != nil {
				s.log().Warn("GeoIP database on disk is unusable; ignoring it", "file", path, "err", err)
				continue
			}
			s.mu.Lock()
			s.paths[k], s.info[k] = path, DBInfo{Edition: ed, Built: meta.Format(time.RFC3339)}
			s.mu.Unlock()
			break
		}
	}
	s.apply()
	s.logLoaded()
}

// apply loads the current paths into the lookup tables.
func (s *Service) apply() {
	s.mu.Lock()
	city, asn := s.paths[City], s.paths[ASN]
	s.mu.Unlock()
	if err := s.Target.Swap(city, asn); err != nil {
		s.log().Warn("GeoIP databases couldn't be loaded", "err", err)
	}
}

func (s *Service) logLoaded() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var have []string
	for _, k := range kinds {
		if i := s.info[k]; i.Edition != "" {
			have = append(have, "dbip-"+string(k)+"-lite "+i.Edition)
		}
	}
	if len(have) > 0 {
		s.log().Info("GeoIP databases: " + strings.Join(have, ", "))
	}
}

// SetEnabled turns downloading on or off. Off also stops using the downloaded files (they
// stay on disk, so turning it on again needs no download).
func (s *Service) SetEnabled(ctx context.Context, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	if err := s.Store.SetSetting(ctx, SettingEnabled, v); err != nil {
		return err
	}
	if !s.Own {
		s.Load(ctx)
	}
	return nil
}

// Check looks for a newer edition of each database and installs it. A failure leaves what
// is loaded as it was. It does nothing when downloading is off or your own files are used.
func (s *Service) Check(ctx context.Context) Status {
	s.checkMu.Lock()
	defer s.checkMu.Unlock()
	if s.Own || !s.Enabled(ctx) {
		return s.Status(ctx)
	}
	s.checking.Store(true)
	defer s.checking.Store(false)
	s.mu.Lock()
	if s.info == nil {
		s.info, s.paths = map[Kind]DBInfo{}, map[Kind]string{}
	}
	s.mu.Unlock()

	var errs []string
	changed := false
	for _, k := range kinds {
		ok, err := s.checkOne(ctx, k)
		if err != nil {
			s.log().Warn("GeoIP download failed", "database", string(k), "err", err)
			errs = append(errs, err.Error())
		}
		changed = changed || ok
	}
	s.mu.Lock()
	s.st.LastChecked = s.now().UnixMilli()
	s.st.LastError = strings.Join(errs, " ")
	p := s.st
	s.mu.Unlock()
	if b, err := json.Marshal(p); err == nil {
		_ = s.Store.SetSetting(ctx, SettingState, string(b))
	}
	if changed {
		s.logLoaded()
	}
	s.checking.Store(false)
	return s.Status(ctx)
}

// checkOne brings one database up to date; it reports whether a new edition was installed.
func (s *Service) checkOne(ctx context.Context, k Kind) (bool, error) {
	base, err := s.base()
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	have := s.info[k].Edition
	s.mu.Unlock()
	now := s.now().UTC()
	// A month's file may not exist yet: this month's, then last month's.
	for _, ym := range []string{now.Format("2006-01"), now.AddDate(0, -1, 0).Format("2006-01")} {
		if have != "" && have >= ym {
			return false, nil // already the newest there can be
		}
		ok, err := s.fetch(ctx, base, k, ym)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	if have != "" {
		return false, nil
	}
	return false, fmt.Errorf("DB-IP has no %s database for this month or last month.", label(k))
}

func label(k Kind) string {
	if k == ASN {
		return "ASN"
	}
	return "City"
}

// friendly turns a failure into a sentence for the page.
func friendly(k Kind, err error) error {
	var en syscall.Errno
	if errors.As(err, &en) && en == syscall.ENOSPC {
		return fmt.Errorf("There isn't enough free disk space to save the %s database.", label(k))
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = errors.New("the download was cut short")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("Couldn't download the %s database: %v", label(k), err)
}

// fetch downloads, verifies and installs one edition. It returns false (and no error) when
// DB-IP doesn't have that month yet.
func (s *Service) fetch(ctx context.Context, base *url.URL, k Kind, ym string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	u := base.JoinPath(remoteName(k, ym))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, friendly(k, err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "SIEMLite")
	resp, err := s.client(base.Host).Do(req)
	if err != nil {
		return false, friendly(k, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		return false, friendly(k, fmt.Errorf("the server answered %s", resp.Status))
	}
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return false, friendly(k, err)
	}
	tmp, err := os.CreateTemp(s.Dir, ".dbip-"+string(k)+"-*.tmp")
	if err != nil {
		return false, friendly(k, err)
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	err = s.save(tmp, resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, friendly(k, err)
	}
	meta, err := Verify(tmp.Name(), k, s.now())
	if err != nil {
		return false, friendly(k, fmt.Errorf("the downloaded file isn't usable (%v), so the previous one stays in use", err))
	}
	final := filepath.Join(s.Dir, FileName(k, ym))
	if err := os.Rename(tmp.Name(), final); err != nil {
		return false, friendly(k, err)
	}
	s.mu.Lock()
	s.paths[k], s.info[k] = final, DBInfo{Edition: ym, Built: meta.Format(time.RFC3339)}
	s.mu.Unlock()
	if s.Enabled(ctx) { // not turned off while it downloaded
		s.apply()
	}
	s.removeOlder(k, ym)
	return true, nil
}

var errTooBig = errors.New("the file is larger than expected")

// capReader fails once more than n bytes have been read.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n < 0 {
		return 0, errTooBig
	}
	if int64(len(p)) > c.n+1 {
		p = p[:c.n+1]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	if c.n < 0 {
		return n, errTooBig
	}
	return n, err
}

// save unpacks the gzip stream in body into f, within the size limits.
func (s *Service) save(f *os.File, body io.Reader) error {
	maxC, maxD := s.MaxCompressed, s.MaxDecompressed
	if maxC <= 0 {
		maxC = MaxCompressed
	}
	if maxD <= 0 {
		maxD = MaxDecompressed
	}
	zr, err := gzip.NewReader(&capReader{r: body, n: maxC})
	if err != nil {
		return errors.New("it isn't a gzip file")
	}
	defer zr.Close()
	if _, err := io.Copy(f, &capReader{r: zr, n: maxD}); err != nil {
		return err
	}
	return f.Sync()
}

// client returns a client that only follows redirects to https on host.
func (s *Service) client(host string) *http.Client {
	var c http.Client
	if s.Client != nil {
		c = *s.Client
	} else {
		c = http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: headerTimeout}).DialContext,
			TLSHandshakeTimeout:   headerTimeout,
			ResponseHeaderTimeout: headerTimeout,
		}}
	}
	c.Timeout = downloadTimeout
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || req.URL.Host != host {
			return fmt.Errorf("it redirected to %s, which isn't %s over https", req.URL.Redacted(), host)
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	return &c
}

// Verify opens an .mmdb file and tries it: the right kind of database, built at a plausible
// time, and a lookup that works (for ASN, 8.8.8.8 must have an autonomous system). It
// returns when the database was built.
func Verify(path string, k Kind, now time.Time) (time.Time, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return time.Time{}, errors.New("it isn't a location database")
	}
	defer r.Close()
	typ := strings.ToLower(r.Metadata.DatabaseType)
	built := r.Metadata.BuildTime()
	if built.Before(time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)) || built.After(now.Add(48*time.Hour)) {
		return built, fmt.Errorf("its build date %s isn't plausible", built.Format("2006-01-02"))
	}
	probe := netip.MustParseAddr("8.8.8.8")
	res := r.Lookup(probe)
	if err := res.Err(); err != nil {
		return built, fmt.Errorf("a test lookup failed: %v", err)
	}
	switch k {
	case City:
		if !strings.Contains(typ, "city") && !strings.Contains(typ, "country") {
			return built, fmt.Errorf("it is a %q database, not a city one", r.Metadata.DatabaseType)
		}
	case ASN:
		if !strings.Contains(typ, "asn") {
			return built, fmt.Errorf("it is a %q database, not an ASN one", r.Metadata.DatabaseType)
		}
		var rec struct {
			Number uint `maxminddb:"autonomous_system_number"`
		}
		if !res.Found() || res.Decode(&rec) != nil || rec.Number == 0 {
			return built, errors.New("a test lookup of 8.8.8.8 found nothing")
		}
	}
	return built, nil
}

// editions lists the stored editions of a database, newest first.
func (s *Service) editions(k Kind) []string {
	ents, _ := os.ReadDir(s.Dir)
	var out []string
	for _, e := range ents {
		if kk, ed, ok := ParseName(e.Name()); ok && kk == k {
			out = append(out, ed)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

// removeOlder deletes the editions older than keep.
func (s *Service) removeOlder(k Kind, keep string) {
	for _, ed := range s.editions(k) {
		if ed < keep {
			_ = os.Remove(filepath.Join(s.Dir, FileName(k, ed)))
		}
	}
}

// cleanTemp removes half-written downloads left by a crash.
func (s *Service) cleanTemp() {
	ents, _ := os.ReadDir(s.Dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".dbip-") && strings.HasSuffix(e.Name(), ".tmp") {
			_ = os.Remove(filepath.Join(s.Dir, e.Name()))
		}
	}
}
