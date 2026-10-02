package intel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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
}

// Feed is a blocklist downloaded on a schedule. Its indicators are stored
// under Name and replaced on every refresh.
type Feed struct {
	Name string
	URL  string
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
	s := &Service{cfg: cfg, store: store, Matcher: NewMatcher()}
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
	s.Matcher.Load(inds)
	s.version.Store(v)
	s.cfg.Logger.Info("threat intel loaded", "indicators", s.Matcher.Size())
	return nil
}

// Run refreshes feeds (immediately, then every FeedInterval) and picks up
// indicator changes until ctx is done.
func (s *Service) Run(ctx context.Context) {
	poll := time.NewTicker(s.cfg.ReloadPoll)
	defer poll.Stop()
	feeds := time.NewTicker(s.cfg.FeedInterval)
	defer feeds.Stop()

	s.refreshFeeds(ctx, true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-feeds.C:
			s.refreshFeeds(ctx, false)
		case <-poll.C:
		}
		if err := s.Load(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logger.Warn("threat intel reload failed", "err", err)
		}
	}
}

// refreshFeeds downloads every feed. At startup, feeds refreshed less than
// FeedInterval ago are skipped so frequent restarts do not hammer providers.
func (s *Service) refreshFeeds(ctx context.Context, startup bool) {
	if len(s.cfg.Feeds) == 0 {
		return
	}
	fresh := map[string]bool{}
	if startup {
		if srcs, err := s.store.ListIntelSources(ctx); err == nil {
			cutoff := time.Now().Add(-s.cfg.FeedInterval).UnixMilli()
			for _, src := range srcs {
				fresh[src.Source] = src.UpdatedAt > cutoff
			}
		}
	}
	for _, f := range s.cfg.Feeds {
		if fresh[f.Name] {
			continue
		}
		n, skipped, err := FetchFeed(ctx, s.cfg.HTTPClient, s.store, f)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.feedErrors.Add(1)
			s.cfg.Logger.Warn("threat intel feed failed; keeping the previous indicators", "feed", f.Name, "err", err)
			continue
		}
		s.cfg.Logger.Info("threat intel feed refreshed", "feed", f.Name, "indicators", n, "skipped_lines", skipped)
	}
	s.lastFetch.Store(time.Now().UnixMilli())
	if err := s.Load(ctx); err != nil && ctx.Err() == nil {
		s.cfg.Logger.Warn("threat intel reload failed", "err", err)
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
	inds, skipped, err := ParseFeed(io.LimitReader(resp.Body, maxFeedBytes), "", f.Name, "")
	if err != nil {
		return 0, skipped, err
	}
	if len(inds) == 0 {
		return 0, skipped, fmt.Errorf("feed %s contained no indicators", f.Name)
	}
	n, err = store.ReplaceIndicators(ctx, f.Name, inds, time.Now().UnixMilli())
	return n, skipped, err
}
