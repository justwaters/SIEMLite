package intel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"siemlite/pkg/storage"
)

// maxFeedBytes caps a downloaded feed.
const maxFeedBytes = 64 << 20

// Store is the indicator storage the service needs.
type Store interface {
	IntelVersion(ctx context.Context) (int64, error)
	AllIndicators(ctx context.Context) ([]storage.Indicator, error)
	ReplaceIndicators(ctx context.Context, source string, inds []storage.Indicator, nowMs int64) (int, error)
	ListIntelSources(ctx context.Context) ([]storage.IntelSource, error)
	DeleteIndicatorSource(ctx context.Context, source string) (int64, error)
	FriendlyValues(ctx context.Context) ([]string, error)
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Feed is a blocklist downloaded on a schedule. Its indicators are stored
// under Name and replaced on every refresh.
type Feed struct {
	Name        string
	URL         string
	Description string // what a match says about the address; kept with each indicator
}

// Config tunes a Service. Zero values select defaults.
type Config struct {
	Feeds        []Feed
	FeedInterval time.Duration // default 6h
	ReloadPoll   time.Duration // how often to look for changes made elsewhere (default 30s)
	HTTPClient   *http.Client
	Logger       *slog.Logger
}

// Stats summarizes the loaded intel.
type Stats struct {
	Indicators  int    `json:"indicators"`
	FeedErrors  uint64 `json:"feed_errors"`
	LastFetchMs int64  `json:"last_fetch,omitempty"`
}

// Service keeps a Matcher in sync with the database (including imports made
// with the CLI while the server runs) and refreshes feeds.
type Service struct {
	cfg     Config
	store   Store
	Matcher *Matcher

	version    atomic.Int64
	feedErrors atomic.Uint64
	lastFetch  atomic.Int64

	feedMu     sync.Mutex        // guards the saved feed choices (read, change, write)
	statusMu   sync.Mutex        // guards errs
	errs       map[string]string // the last error of each feed that failed, by id
	refreshing atomic.Bool

	triedMu sync.Mutex
	tried   map[string]time.Time // when each feed was last downloaded or tried in this run, by name

	actMu    sync.Mutex
	actNow   string // the feed being downloaded
	actDone  int    // feeds finished in this round
	actTotal int    // feeds in this round (0 when none is running)
}

// Activity reports a round of downloads in progress: which feed is being fetched now, how many
// are done, and how many there are in all (total is 0 when nothing is downloading).
func (s *Service) Activity() (now string, done, total int) {
	s.actMu.Lock()
	defer s.actMu.Unlock()
	return s.actNow, s.actDone, s.actTotal
}

func (s *Service) setActivity(now string, done, total int) {
	s.actMu.Lock()
	s.actNow, s.actDone, s.actTotal = now, done, total
	s.actMu.Unlock()
}

// NewService returns a service; call Load before ingesting, then Run.
func NewService(store Store, cfg Config) *Service {
	if cfg.FeedInterval <= 0 {
		cfg.FeedInterval = 6 * time.Hour
	}
	if cfg.ReloadPoll <= 0 {
		cfg.ReloadPoll = 30 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 2 * time.Minute}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Service{cfg: cfg, store: store, Matcher: NewMatcher(), errs: map[string]string{}, tried: map[string]time.Time{}}
	s.version.Store(-1)
	return s
}

// Load reads the indicators into the matcher if they changed.
func (s *Service) Load(ctx context.Context) error {
	v, err := s.store.IntelVersion(ctx)
	if err != nil {
		return err
	}
	if v == s.version.Load() {
		return nil
	}
	inds, err := s.store.AllIndicators(ctx)
	if err != nil {
		return err
	}
	friendly, err := s.store.FriendlyValues(ctx)
	if err != nil {
		return err
	}
	s.Matcher.Load(inds, friendly)
	s.Matcher.SetMeta(s.listMeta())
	s.version.Store(v)
	s.cfg.Logger.Info("threat intel loaded", "indicators", s.Matcher.Size())
	return nil
}

// Run keeps the feeds up to date, and picks up indicator changes, until ctx is done. A feed is
// downloaded again only when its last download is older than FeedInterval, so a restart (an
// update, say) does not download again what is already here.
func (s *Service) Run(ctx context.Context) {
	poll := time.NewTicker(s.cfg.ReloadPoll)
	defer poll.Stop()
	// Look often for feeds that have come due: the schedule follows each feed's last download,
	// not when SIEMLite started.
	feeds := time.NewTicker(min(s.cfg.FeedInterval, 15*time.Minute))
	defer feeds.Stop()

	s.refreshRound(ctx, refreshDue)
	for {
		select {
		case <-ctx.Done():
			return
		case <-feeds.C:
			s.refreshRound(ctx, refreshDue)
		case <-poll.C:
		}
		if err := s.Load(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logger.Warn("threat intel reload failed", "err", err)
		}
	}
}

// How much a round of downloads covers.
type refreshMode int

const (
	refreshAll refreshMode = iota // every chosen feed (the Refresh button)
	refreshDue                    // the feeds last downloaded more than FeedInterval ago, which didn't fail to download in the last FeedInterval
	refreshNew                    // the feeds with nothing downloaded yet, which didn't fail to download in the last FeedInterval (after a feed is chosen)
)

// refreshRound is refreshFeeds, unless a round is already running (one started by the Refresh button
// or by choosing a feed): rounds never overlap, so two don't download the same feed at once. The
// next check picks up whatever this one skipped.
func (s *Service) refreshRound(ctx context.Context, mode refreshMode) {
	if !s.refreshing.CompareAndSwap(false, true) {
		return
	}
	defer s.refreshing.Store(false)
	s.refreshFeeds(ctx, mode)
}

// pending picks the feeds a round downloads.
func (s *Service) pending(ctx context.Context, feeds []Feed, mode refreshMode) []Feed {
	if mode == refreshAll {
		return feeds
	}
	updated := map[string]int64{}
	if srcs, err := s.store.ListIntelSources(ctx); err == nil {
		for _, src := range srcs {
			updated[src.Source] = src.UpdatedAt
		}
	} else {
		return feeds // can't tell what is here, so don't skip anything
	}
	now := time.Now()
	cutoff := now.Add(-s.cfg.FeedInterval).UnixMilli()
	s.triedMu.Lock()
	defer s.triedMu.Unlock()
	// Forget feeds that are no longer chosen, so the record holds only the feeds in use.
	chosen := make(map[string]bool, len(feeds))
	for _, f := range feeds {
		chosen[f.Name] = true
	}
	for name := range s.tried {
		if !chosen[name] {
			delete(s.tried, name)
		}
	}
	var out []Feed
	for _, f := range feeds {
		at, have := updated[f.Name]
		if now.Sub(s.tried[f.Name]) < s.cfg.FeedInterval {
			continue // downloaded or failed a moment ago
		}
		if (mode == refreshNew && !have) || (mode == refreshDue && (!have || at <= cutoff)) {
			out = append(out, f)
		}
	}
	return out
}

// refreshFeeds downloads the feeds the mode asks for, one at a time.
func (s *Service) refreshFeeds(ctx context.Context, mode refreshMode) {
	feeds := s.pending(ctx, s.activeFeeds(ctx), mode)
	todo := len(feeds)
	if todo == 0 {
		return
	}
	done := 0
	defer s.setActivity("", 0, 0)
	for _, f := range feeds {
		s.setActivity(f.Name, done, todo)
		done++
		id := s.feedID(f)
		s.triedMu.Lock()
		s.tried[f.Name] = time.Now()
		s.triedMu.Unlock()
		n, skipped, err := FetchFeed(ctx, s.cfg.HTTPClient, s.store, f)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.feedErrors.Add(1)
			s.setErr(id, err.Error())
			s.cfg.Logger.Warn("threat intel feed failed; keeping the previous indicators", "feed", f.Name, "err", err)
			continue
		}
		s.setErr(id, "")
		s.cfg.Logger.Info("threat intel feed refreshed", "feed", f.Name, "indicators", n, "skipped_lines", skipped)
	}
	s.lastFetch.Store(time.Now().UnixMilli())
	if err := s.Load(ctx); err != nil && ctx.Err() == nil {
		s.cfg.Logger.Warn("threat intel reload failed", "err", err)
	}
}

// feedID is the id the card knows a feed by.
func (s *Service) feedID(f Feed) string {
	for _, p := range Presets {
		if p.Name == f.Name {
			return p.ID
		}
	}
	return "custom:" + f.Name
}

func (s *Service) setErr(id, msg string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if msg == "" {
		delete(s.errs, id)
	} else {
		s.errs[id] = msg
	}
}

// Stats returns a snapshot.
func (s *Service) Stats() Stats {
	return Stats{Indicators: s.Matcher.Size(), FeedErrors: s.feedErrors.Load(), LastFetchMs: s.lastFetch.Load()}
}

// FetchFeed downloads a feed and replaces its source's indicators. A feed
// that downloads but yields no indicators is treated as an error, so a
// broken mirror cannot silently empty a blocklist.
func FetchFeed(ctx context.Context, client *http.Client, store Store, f Feed) (n, skipped int, err error) {
	if !strings.HasPrefix(f.URL, "https://") && !strings.HasPrefix(f.URL, "http://") {
		return 0, 0, fmt.Errorf("feed URL must be http(s): %q", f.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "SIEMLite")
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("GET %s: %s", f.URL, resp.Status)
	}
	body := &io.LimitedReader{R: resp.Body, N: maxFeedBytes + 1}
	inds, skipped, err := ParseFeed(body, "", f.Name, f.Description)
	if err != nil {
		return 0, skipped, err
	}
	if body.N <= 0 {
		// A feed cut off in the middle could end on a half-written address; keep the indicators we have.
		return 0, skipped, fmt.Errorf("feed %s is larger than %d MiB, so it was not used", f.Name, maxFeedBytes>>20)
	}
	if len(inds) == 0 {
		return 0, skipped, fmt.Errorf("feed %s contained no indicators", f.Name)
	}
	n, err = store.ReplaceIndicators(ctx, f.Name, inds, time.Now().UnixMilli())
	return n, skipped, err
}

// listMeta is what is known about each list a match can come from: the feeds on offer, and
// feeds set with -intel-feed. Lists imported by hand have no entry.
func (s *Service) listMeta() map[string]Meta {
	meta := map[string]Meta{}
	for _, f := range s.cfg.Feeds {
		meta[f.Name] = Meta{Category: "Custom feed", Reference: siteOf(f.URL)}
	}
	for _, p := range Presets {
		meta[p.Name] = Meta{Category: p.Category, Confidence: p.Confidence, Reference: p.Terms}
	}
	return meta
}

// siteOf reduces a feed's address to its site (https://host), dropping any login, path, query or
// fragment: a feed address can carry a key, and a match is shown to everyone who can read events.
func siteOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
