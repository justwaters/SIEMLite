package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"siemlite/pkg/integrations"
)

const feedsSettingKey = "threatfeeds"

// feedSettings is what an admin chose on the Threat feeds card.
type feedSettings struct {
	Selected []string `json:"selected"` // preset ids
}

// FeedState is one feed as the card shows it.
type FeedState struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Terms       string `json:"terms,omitempty"`
	License     string `json:"license,omitempty"`
	Custom      bool   `json:"custom"` // set with -intel-feed, not from this card
	Selected    bool   `json:"selected"`
	Indicators  int    `json:"indicators"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
	Error       string `json:"error,omitempty"`
}

// FeedsView is the Feeds section of the Intel page.
type FeedsView struct {
	Feeds []FeedState `json:"feeds"`
}

func (s *Service) loadFeedSettings(ctx context.Context) (feedSettings, error) {
	raw, err := s.store.Setting(ctx, feedsSettingKey, "")
	if err != nil {
		return feedSettings{}, err
	}
	var st feedSettings
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			return feedSettings{}, fmt.Errorf("saved threat feed settings are damaged: %w", err)
		}
	}
	return st, nil
}

func (s *Service) saveFeedSettings(ctx context.Context, st feedSettings) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.store.SetSetting(ctx, feedsSettingKey, string(b))
}

// activeFeeds are the feeds to download: those set with -intel-feed, and the
// chosen presets.
func (s *Service) activeFeeds(ctx context.Context) []Feed {
	feeds := append([]Feed(nil), s.cfg.Feeds...)
	st, err := s.loadFeedSettings(ctx)
	if err != nil {
		return feeds
	}
	for _, id := range st.Selected {
		if p, ok := PresetByID(id); ok {
			feeds = append(feeds, Feed{Name: p.Name, URL: p.URL, Description: p.Label})
		}
	}
	return feeds
}

func (s *Service) dropPresets(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if p, ok := PresetByID(id); ok {
			if _, err := s.store.DeleteIndicatorSource(ctx, p.Name); err != nil {
				return err
			}
		}
	}
	return s.Load(ctx)
}

// SetFeeds chooses which presets to download. Feeds taken off the list have
// their indicators removed; new ones are downloaded now, in the background.
func (s *Service) SetFeeds(ctx context.Context, ids []string) error {
	seen := map[string]bool{}
	var keep []string
	for _, id := range ids {
		if _, ok := PresetByID(id); !ok {
			return integrations.InputError(fmt.Sprintf("%q is not a known feed.", id))
		}
		if !seen[id] {
			seen[id] = true
			keep = append(keep, id)
		}
	}
	sort.Strings(keep)
	s.feedMu.Lock()
	st, err := s.loadFeedSettings(ctx)
	if err != nil {
		s.feedMu.Unlock()
		return err
	}
	var removed []string
	for _, id := range st.Selected {
		if !seen[id] {
			removed = append(removed, id)
		}
	}
	st.Selected = keep
	err = s.saveFeedSettings(ctx, st)
	s.feedMu.Unlock()
	if err != nil {
		return err
	}
	s.statusMu.Lock()
	for _, id := range removed {
		delete(s.errs, id)
	}
	s.statusMu.Unlock()
	if err := s.dropPresets(ctx, removed); err != nil {
		return err
	}
	s.RefreshAsync()
	return nil
}

// RefreshAsync downloads the chosen feeds now, in the background. Feeds are
// fetched one at a time and a second request while one runs is dropped.
func (s *Service) RefreshAsync() {
	if !s.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.refreshing.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		s.refreshFeeds(ctx, false)
	}()
}

// Feeds describes every preset and every -intel-feed feed.
func (s *Service) Feeds(ctx context.Context) (FeedsView, error) {
	st, err := s.loadFeedSettings(ctx)
	if err != nil {
		return FeedsView{}, err
	}
	srcs, err := s.store.ListIntelSources(ctx)
	if err != nil {
		return FeedsView{}, err
	}
	by := map[string][2]int64{}
	for _, src := range srcs {
		by[src.Source] = [2]int64{int64(src.Count), src.UpdatedAt}
	}
	chosen := map[string]bool{}
	for _, id := range st.Selected {
		chosen[id] = true
	}
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	var v FeedsView
	for _, p := range Presets {
		fs := FeedState{ID: p.ID, Name: p.Name, Description: p.Description, Terms: p.Terms, License: p.License, Selected: chosen[p.ID], Error: s.errs[p.ID]}
		if chosen[p.ID] {
			fs.Indicators, fs.UpdatedAt = int(by[p.Name][0]), by[p.Name][1]
		}
		v.Feeds = append(v.Feeds, fs)
	}
	for _, f := range s.cfg.Feeds {
		fs := FeedState{ID: "custom:" + f.Name, Name: f.Name, Custom: true, Selected: true, Indicators: int(by[f.Name][0]), UpdatedAt: by[f.Name][1], Error: s.errs["custom:"+f.Name]}
		v.Feeds = append(v.Feeds, fs)
	}
	return v, nil
}
