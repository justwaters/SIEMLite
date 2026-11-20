package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

func TestHaversine(t *testing.T) {
	// London to Sydney is about 17,000 km.
	if d := Haversine(51.5074, -0.1278, -33.8688, 151.2093); d < 16900 || d > 17100 {
		t.Errorf("London-Sydney = %.0f km", d)
	}
	if d := Haversine(51.5, -0.1, 51.5, -0.1); d != 0 {
		t.Errorf("same point = %v", d)
	}
	// London to Paris is about 344 km.
	if d := Haversine(51.5074, -0.1278, 48.8566, 2.3522); d < 335 || d > 350 {
		t.Errorf("London-Paris = %.0f km", d)
	}
	// Across the antimeridian is short.
	if d := Haversine(0, 179.9, 0, -179.9); d > 30 {
		t.Errorf("antimeridian = %.0f km", d)
	}
}

func login(ip string, lat, lon float64, at time.Time) storage.Login {
	return storage.Login{User: "u", IP: ip, Lat: lat, Lon: lon, TimeMs: at.UnixMilli()}
}

func TestImprobable(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	london := func(at time.Time) storage.Login { return login("1.1.1.1", 51.5074, -0.1278, at) }
	sydney := func(at time.Time) storage.Login { return login("2.2.2.2", -33.8688, 151.2093, at) }
	paris := func(at time.Time) storage.Login { return login("3.3.3.3", 48.8566, 2.3522, at) }
	nan, inf := math.NaN(), math.Inf(1)
	cases := []struct {
		name      string
		prev, cur storage.Login
		want      bool
	}{
		{"london to sydney in 2h", london(t0), sydney(t0.Add(2 * time.Hour)), true},
		{"london to paris in 3h", london(t0), paris(t0.Add(3 * time.Hour)), false},
		{"london to paris in 1 minute", london(t0), paris(t0.Add(time.Minute)), true},
		{"london to sydney in 24h", london(t0), sydney(t0.Add(24 * time.Hour)), false},
		{"same time", london(t0), sydney(t0), false},
		{"time goes backwards", london(t0), sydney(t0.Add(-time.Hour)), false},
		{"seconds apart counts as a minute", london(t0), sydney(t0.Add(time.Second)), true},
		{"under 200 km", login("a", 51.5, -0.1, t0), login("b", 52.0, 0.5, t0.Add(time.Minute)), false},
		{"same ip", london(t0), login("1.1.1.1", -33.8688, 151.2093, t0.Add(time.Hour)), false},
		{"nan lat", london(t0), login("x", nan, 0, t0.Add(time.Hour)), false},
		{"inf lon", london(t0), login("x", 0, inf, t0.Add(time.Hour)), false},
		{"lat out of range", london(t0), login("x", 91, 0, t0.Add(time.Hour)), false},
		{"lon out of range", login("x", 0, -181, t0), sydney(t0.Add(time.Hour)), false},
	}
	for _, c := range cases {
		v, got := Improbable(c.prev, c.cur, 900)
		if got != c.want {
			t.Errorf("%s: improbable = %v (%+v), want %v", c.name, got, v, c.want)
		}
	}
	v, _ := Improbable(london(t0), sydney(t0.Add(2*time.Hour)), 900)
	if math.Abs(v.Hours-2) > 1e-9 || v.Kmh < 8000 || v.Kmh > 8600 {
		t.Errorf("verdict = %+v", v)
	}
}

func TestTravelDetailText(t *testing.T) {
	a := storage.Login{IP: "1.1.1.1", City: "London", Country: "GB"}
	b := storage.Login{IP: "2.2.2.2", City: "Sydney", Country: "AU"}
	got := travelDetail(a, b, Verdict{DistanceKm: 17000, Hours: 2 + 10.0/60, Kmh: 7800})
	want := "London, GB (1.1.1.1) -> Sydney, AU (2.2.2.2): 17,000 km in 2h10m (7,800 km/h)"
	if got != want {
		t.Errorf("detail = %q, want %q", got, want)
	}
}

// --- engine ---

type spot struct {
	city, country string
	lat, lon      float64
}

var (
	london = spot{"London", "GB", 51.5074, -0.1278}
	sydney = spot{"Sydney", "AU", -33.8688, 151.2093}
	paris  = spot{"Paris", "FR", 48.8566, 2.3522}
)

func enrichment(p *spot, ip string) json.RawMessage {
	if p == nil {
		return nil
	}
	b, _ := json.Marshal(map[string]any{"src_endpoint": map[string]any{"ip": ip, "location": map[string]any{
		"city": p.city, "country": p.country, "coordinates": []float64{p.lon, p.lat}}}})
	return b
}

func signin(user, ip, action string, p *spot, at time.Time) storage.Record {
	r := storage.Record{Timestamp: at.UnixMilli(), CategoryUID: 3, ClassUID: 3002, SeverityID: 1, SrcIP: ip, UserName: user,
		Message: user + " " + action, RawData: user + " " + action + " from " + ip, Fields: json.RawMessage(fmt.Sprintf(`{"action":%q}`, action)),
		Enrichment: enrichment(p, ip)}
	if p != nil {
		r.SrcCountry = p.country
	}
	return r
}

func insert(t *testing.T, repo *storage.Repository, recs ...storage.Record) {
	t.Helper()
	if err := repo.InsertBatch(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
}

func travelSetup(t *testing.T) (*storage.Repository, *Engine, *[]Opened) {
	t.Helper()
	repo, _, eng := setup(t)
	if err := repo.EnsureTravelRule(context.Background()); err != nil {
		t.Fatal(err)
	}
	var told []Opened
	eng.SetNotifier(func(_ context.Context, o Opened) { told = append(told, o) })
	return repo, eng, &told
}

func check(t *testing.T, eng *Engine) Result {
	t.Helper()
	res, err := eng.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestTravelLondonThenSydney(t *testing.T) {
	repo, eng, told := travelSetup(t)
	t0 := time.Now().Add(-5 * time.Hour)
	insert(t, repo,
		signin("alice", "81.2.69.1", "auth.success", &london, t0),
		signin("alice", "1.128.0.1", "auth.success", &sydney, t0.Add(2*time.Hour+10*time.Minute)))
	if res := check(t, eng); res.Opened != 1 {
		t.Fatalf("result = %+v", res)
	}
	got := alertsByRule(t, repo)[storage.TravelRuleName]
	if len(got) != 1 || got[0].GroupValue != "alice" || got[0].Severity != 4 || got[0].GroupBy != "user" || got[0].Status != "open" {
		t.Fatalf("alerts = %+v", got)
	}
	if len(*told) != 1 || (*told)[0].Group != "alice" || !strings.Contains((*told)[0].Detail, "London, GB") ||
		!strings.Contains((*told)[0].Detail, "Sydney, AU") || !strings.Contains((*told)[0].Detail, "81.2.69.1") {
		t.Fatalf("told = %+v", *told)
	}
	// Nothing new: nothing changes.
	if res := check(t, eng); res.Opened+res.Updated != 0 {
		t.Errorf("second check = %+v", res)
	}
	// The same pair again (Sydney then London later) updates the alert and doesn't announce it.
	insert(t, repo, signin("alice", "81.2.69.1", "auth.success", &london, t0.Add(2*time.Hour+40*time.Minute)))
	if res := check(t, eng); res.Opened != 0 || res.Updated != 1 {
		t.Fatalf("repeat = %+v", res)
	}
	got = alertsByRule(t, repo)[storage.TravelRuleName]
	if len(got) != 1 || got[0].Count != 2 || len(*told) != 1 {
		t.Errorf("after the repeat: alerts = %+v, told %d", got, len(*told))
	}
}

func TestTravelPlausibleAndIgnored(t *testing.T) {
	repo, eng, told := travelSetup(t)
	t0 := time.Now().Add(-5 * time.Hour)
	insert(t, repo,
		// London then Paris in 3 hours is fine.
		signin("bob", "81.2.69.1", "auth.success", &london, t0),
		signin("bob", "5.5.5.5", "auth.success", &paris, t0.Add(3*time.Hour)),
		// A user whose events have no coordinates.
		signin("carol", "81.2.69.1", "auth.success", nil, t0),
		signin("carol", "1.128.0.1", "auth.success", nil, t0.Add(time.Hour)),
		// Failures aren't sign-ins.
		signin("dave", "81.2.69.1", "auth.failure", &london, t0),
		signin("dave", "1.128.0.1", "auth.failure", &sydney, t0.Add(time.Hour)),
		// Different users don't mix.
		signin("erin", "81.2.69.1", "auth.success", &london, t0),
		signin("frank", "1.128.0.1", "auth.success", &sydney, t0.Add(time.Hour)),
		// A success after a failure from far away isn't a pair either.
		signin("gina", "81.2.69.1", "auth.success", &london, t0),
		signin("gina", "1.128.0.1", "auth.failure", &sydney, t0.Add(time.Hour)))
	check(t, eng)
	if got := alertsByRule(t, repo)[storage.TravelRuleName]; len(got) != 0 {
		t.Errorf("alerts = %+v", got)
	}
	if len(*told) != 0 {
		t.Errorf("told = %+v", *told)
	}
}

func TestTravelUserCaseAndOtherShapes(t *testing.T) {
	repo, eng, _ := travelSetup(t)
	t0 := time.Now().Add(-5 * time.Hour)
	insert(t, repo,
		signin("Alice", "81.2.69.1", "vpn.login", &london, t0),
		signin("alice", "1.128.0.1", "signin", &sydney, t0.Add(time.Hour)))
	check(t, eng)
	if got := alertsByRule(t, repo)[storage.TravelRuleName]; len(got) != 1 {
		t.Errorf("alerts = %+v", got)
	}
}

func TestTravelLateOlderEvent(t *testing.T) {
	repo, eng, _ := travelSetup(t)
	t0 := time.Now().Add(-10 * time.Hour)
	insert(t, repo, signin("alice", "1.128.0.1", "auth.success", &sydney, t0.Add(5*time.Hour)))
	check(t, eng)
	// An older London sign-in arrives afterwards: it is the earlier of the pair.
	insert(t, repo, signin("alice", "81.2.69.1", "auth.success", &london, t0.Add(4*time.Hour)))
	if res := check(t, eng); res.Opened != 0 {
		t.Fatalf("a late event is compared with what came before it, not after: %+v", res)
	}
	// A later London sign-in (arriving late too, but after the Sydney one in time) is the pair.
	insert(t, repo, signin("alice", "81.2.69.2", "auth.success", &london, t0.Add(6*time.Hour)))
	if res := check(t, eng); res.Opened != 1 {
		t.Fatalf("result = %+v", res)
	}
}

func TestTravelRuleOffAndQueryEdit(t *testing.T) {
	repo, eng, _ := travelSetup(t)
	ctx := context.Background()
	rules, _ := repo.ListRules(ctx)
	var ru storage.Rule
	for _, r := range rules {
		if r.Name == storage.TravelRuleName {
			ru = r
		}
	}
	if !ru.Builtin || !ru.Enabled || ru.Severity != 4 || ru.Threshold != 900 || ru.GroupBy != "user" {
		t.Fatalf("rule = %+v", ru)
	}
	ru.Enabled = false
	if _, err := repo.SaveRule(ctx, ru, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-5 * time.Hour)
	insert(t, repo,
		signin("alice", "81.2.69.1", "auth.success", &london, t0),
		signin("alice", "1.128.0.1", "auth.success", &sydney, t0.Add(time.Hour)))
	check(t, eng)
	if got := alertsByRule(t, repo)[storage.TravelRuleName]; len(got) != 0 {
		t.Fatalf("a rule that is off raised %+v", got)
	}
	// Switched back on, it doesn't go back over what it skipped.
	ru.Enabled = true
	repo.SaveRule(ctx, ru, time.Now().UnixMilli())
	check(t, eng)
	if got := alertsByRule(t, repo)[storage.TravelRuleName]; len(got) != 0 {
		t.Fatalf("raised for events from while it was off: %+v", got)
	}
	// An edited query (a different action) is what counts as a sign-in.
	ru.Query = "action=custom.ok"
	repo.SaveRule(ctx, ru, time.Now().UnixMilli())
	insert(t, repo,
		signin("zed", "81.2.69.1", "custom.ok", &london, t0.Add(2*time.Hour)),
		signin("zed", "1.128.0.1", "custom.ok", &sydney, t0.Add(3*time.Hour)),
		signin("yan", "81.2.69.1", "auth.success", &london, t0.Add(2*time.Hour)),
		signin("yan", "1.128.0.1", "auth.success", &sydney, t0.Add(3*time.Hour)))
	check(t, eng)
	got := alertsByRule(t, repo)[storage.TravelRuleName]
	if len(got) != 1 || got[0].GroupValue != "zed" {
		t.Errorf("alerts = %+v", got)
	}
}

// A storage failure raises nothing and leaves the range to be checked again.
type failsTravel struct {
	*storage.Repository
	failing bool
}

func (f *failsTravel) PreviousLogin(ctx context.Context, ru storage.Rule, user string, ms, seq, lb int64) (*storage.Login, error) {
	if f.failing {
		return nil, fmt.Errorf("disk on fire")
	}
	return f.Repository.PreviousLogin(ctx, ru, user, ms, seq, lb)
}

func TestTravelFailureRetries(t *testing.T) {
	repo, _, _ := travelSetup(t)
	store := &failsTravel{Repository: repo, failing: true}
	eng := New(store, nil)
	t0 := time.Now().Add(-5 * time.Hour)
	insert(t, repo,
		signin("alice", "81.2.69.1", "auth.success", &london, t0),
		signin("alice", "1.128.0.1", "auth.success", &sydney, t0.Add(time.Hour)))
	check(t, eng)
	if got := alertsByRule(t, repo)[storage.TravelRuleName]; len(got) != 0 {
		t.Fatalf("raised while failing: %+v", got)
	}
	store.failing = false
	check(t, eng)
	if got := alertsByRule(t, repo)[storage.TravelRuleName]; len(got) != 1 {
		t.Errorf("after recovering: %+v", got)
	}
}
