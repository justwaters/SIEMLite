package update

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Setting(_ context.Context, k, def string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[k]; ok {
		return v, nil
	}
	return def, nil
}
func (s *memStore) SetSetting(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

func TestValidateAuto(t *testing.T) {
	v, err := ValidateAuto(AutoSettings{Enabled: true, Days: []int{6, 1, 1}, Times: []string{"23:05", " 3:00", "03:00"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v.Days, []int{1, 6}) || !reflect.DeepEqual(v.Times, []string{"03:00", "23:05"}) {
		t.Errorf("tidied to %+v", v)
	}
	if v, _ := ValidateAuto(AutoSettings{Days: []int{0, 1, 2, 3, 4, 5, 6}}); len(v.Days) != 0 {
		t.Errorf("all seven days should mean every day: %v", v.Days)
	}
	for name, in := range map[string]AutoSettings{
		"no time while on": {Enabled: true},
		"bad day":          {Days: []int{7}},
		"negative day":     {Days: []int{-1}},
		"not a time":       {Times: []string{"25:00"}},
		"seconds":          {Times: []string{"03:00:00"}},
		"empty":            {Times: []string{""}},
		"too many":         {Times: []string{"01:00", "02:00", "03:00", "04:00", "05:00"}},
	} {
		if _, err := ValidateAuto(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// Off with no times is fine (nothing to run).
	if _, err := ValidateAuto(AutoSettings{}); err != nil {
		t.Error(err)
	}
}

func TestNextAuto(t *testing.T) {
	utc := time.UTC
	at := func(y int, m time.Month, d, h, mi int) time.Time { return time.Date(y, m, d, h, mi, 0, 0, utc) }
	// 2026-11-20 is a Friday.
	set := AutoSettings{Times: []string{"03:00", "15:30"}}
	for _, c := range []struct {
		name string
		set  AutoSettings
		from time.Time
		want time.Time
	}{
		{"later today", set, at(2026, 11, 20, 10, 0), at(2026, 11, 20, 15, 30)},
		{"after the last time: tomorrow's first", set, at(2026, 11, 20, 16, 0), at(2026, 11, 21, 3, 0)},
		{"exactly at a time is not after it", set, at(2026, 11, 20, 3, 0), at(2026, 11, 20, 15, 30)},
		{"weekdays only, from Friday evening: Monday", AutoSettings{Days: []int{1, 2, 3, 4, 5}, Times: []string{"03:00"}}, at(2026, 11, 20, 16, 0), at(2026, 11, 23, 3, 0)},
		{"Sunday only", AutoSettings{Days: []int{0}, Times: []string{"04:15"}}, at(2026, 11, 20, 16, 0), at(2026, 11, 22, 4, 15)},
		{"the same weekday a week on", AutoSettings{Days: []int{5}, Times: []string{"03:00"}}, at(2026, 11, 20, 3, 0), at(2026, 11, 27, 3, 0)},
		{"month end", AutoSettings{Times: []string{"01:00"}}, at(2026, 12, 31, 2, 0), at(2027, 1, 1, 1, 0)},
	} {
		if got := NextAuto(c.set, c.from, utc); !got.Equal(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if !NextAuto(AutoSettings{}, at(2026, 1, 1, 0, 0), utc).IsZero() {
		t.Error("no times should give no next time")
	}
	// A zone with daylight saving: the schedule keeps its wall-clock time.
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tz database")
	}
	got := NextAuto(AutoSettings{Times: []string{"03:00"}}, time.Date(2026, 3, 7, 12, 0, 0, 0, ny), ny) // spring forward is 8 March
	if got.Hour() != 3 || got.Day() != 8 {
		t.Errorf("across the spring change: %v", got)
	}
	got = NextAuto(AutoSettings{Times: []string{"02:30"}}, time.Date(2026, 3, 7, 12, 0, 0, 0, ny), ny) // 02:30 doesn't exist on 8 March
	if !got.After(time.Date(2026, 3, 7, 12, 0, 0, 0, ny)) || got.Sub(time.Date(2026, 3, 7, 12, 0, 0, 0, ny)) > 48*time.Hour {
		t.Errorf("in the skipped hour: %v", got)
	}
}

func newAuto(t *testing.T, tag string) (*Auto, *memStore, *time.Time) {
	t.Helper()
	c := fakeRelease(t, tag, "new program", false)
	store := &memStore{}
	clock := time.Date(2026, 11, 20, 2, 59, 0, 0, time.UTC)
	return &Auto{Checker: c, Store: store, Now: func() time.Time { return clock }, Loc: time.UTC}, store, &clock
}

func TestAutoInstallsAtTheScheduledTime(t *testing.T) {
	ctx := context.Background()
	a, _, clock := newAuto(t, "v0.10")
	var backups, restarts int
	var from, to string
	restarted := make(chan struct{}, 1)
	a.Backup = func(context.Context) error { backups++; return nil }
	a.Restart = func() { restarts++; restarted <- struct{}{} }
	a.Done = func(f, t string) { from, to = f, t }
	if _, err := a.Save(ctx, AutoSettings{Enabled: true, Times: []string{"03:00"}, BackupFirst: true}); err != nil {
		t.Fatal(err)
	}
	if a.Tick(ctx) {
		t.Fatal("the first look should only arm the schedule")
	}
	*clock = clock.Add(30 * time.Second) // 02:59:30
	if a.Tick(ctx) || backups != 0 {
		t.Fatal("ran before its time")
	}
	*clock = clock.Add(31 * time.Second) // 03:00:01
	if !a.Tick(ctx) {
		t.Fatalf("did not install: %+v", a.State(ctx).Last)
	}
	<-restarted
	if backups != 1 || restarts != 1 || from != "v0.9" || to != "v0.10" {
		t.Errorf("backups=%d restarts=%d from=%q to=%q", backups, restarts, from, to)
	}
	if b, _ := os.ReadFile(a.Checker.Exe); string(b) != "new program" {
		t.Errorf("program is %q", b)
	}
	st := a.State(ctx)
	if st.Last == nil || !st.Last.OK || st.Next == 0 || !time.UnixMilli(st.Next).After(*clock) {
		t.Errorf("state = %+v", st)
	}
}

func TestAutoDoesNothingWhenOffOrUpToDate(t *testing.T) {
	ctx := context.Background()
	a, _, clock := newAuto(t, "v0.9") // the latest release is the one running
	a.Backup = func(context.Context) error { t.Error("backed up with nothing to install"); return nil }
	a.Restart = func() { t.Error("restarted") }
	if a.Tick(ctx) {
		t.Fatal("ran while off")
	}
	a.Save(ctx, AutoSettings{Enabled: true, Times: []string{"03:00"}, BackupFirst: true})
	a.Tick(ctx)
	*clock = clock.Add(2 * time.Minute)
	if a.Tick(ctx) {
		t.Fatal("installed with nothing newer")
	}
	if l := a.State(ctx).Last; l == nil || !l.OK {
		t.Errorf("last = %+v", l)
	}
}

func TestAutoStopsWhenTheBackupFails(t *testing.T) {
	ctx := context.Background()
	a, _, clock := newAuto(t, "v0.10")
	a.Backup = func(context.Context) error { return errors.New("disk full") }
	a.Restart = func() { t.Error("restarted after a failed backup") }
	a.Save(ctx, AutoSettings{Enabled: true, Times: []string{"03:00"}, BackupFirst: true})
	a.Tick(ctx)
	*clock = clock.Add(2 * time.Minute)
	if a.Tick(ctx) {
		t.Fatal("installed without a backup")
	}
	if b, _ := os.ReadFile(a.Checker.Exe); string(b) != "old" {
		t.Errorf("program changed to %q", b)
	}
	if l := a.State(ctx).Last; l == nil || l.OK {
		t.Errorf("last = %+v", l)
	}
	// With the backup option off, the same failure doesn't matter.
	a.Save(ctx, AutoSettings{Enabled: true, Times: []string{"03:00", "04:00"}, BackupFirst: false})
	a.Tick(ctx) // re-armed by the changed schedule
	*clock = clock.Add(2 * time.Hour)
	restarted := make(chan struct{}, 1)
	a.Restart = func() { restarted <- struct{}{} }
	if !a.Tick(ctx) {
		t.Fatalf("did not install without the backup option: %+v", a.State(ctx).Last)
	}
	<-restarted
}

func TestAutoChangingTheScheduleDoesNotRunATimeThatPassed(t *testing.T) {
	ctx := context.Background()
	a, _, clock := newAuto(t, "v0.10")
	a.Restart = func() { t.Error("restarted") }
	*clock = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	a.Save(ctx, AutoSettings{Enabled: true, Times: []string{"03:00"}})
	if a.Tick(ctx) {
		t.Fatal("ran a time that had already passed today")
	}
	*clock = clock.Add(time.Hour)
	if a.Tick(ctx) {
		t.Fatal("ran at the wrong time")
	}
}

func TestAutoRefusesWhereItCannotInstall(t *testing.T) {
	ctx := context.Background()
	a, _, clock := newAuto(t, "v0.10")
	a.Checker.Exe = "/nonexistent-dir/siemlite" // not writable
	a.Restart = func() { t.Error("restarted") }
	a.Save(ctx, AutoSettings{Enabled: true, Times: []string{"03:00"}})
	a.Tick(ctx)
	*clock = clock.Add(2 * time.Minute)
	if a.Tick(ctx) {
		t.Fatal("installed where it can't")
	}
	if st := a.State(ctx); st.CanApply || st.Last == nil || st.Last.OK {
		t.Errorf("state = %+v", st)
	}
}

func TestAutoSettingsSurviveBadSavedData(t *testing.T) {
	ctx := context.Background()
	a, store, _ := newAuto(t, "v0.10")
	if got := a.Settings(ctx); got.Enabled || len(got.Times) != 1 {
		t.Errorf("default = %+v", got)
	}
	store.SetSetting(ctx, SettingKey, "{not json")
	if got := a.Settings(ctx); got.Enabled {
		t.Errorf("garbage turned it on: %+v", got)
	}
	store.SetSetting(ctx, SettingKey, `{"enabled":true,"times":["99:99"]}`)
	if got := a.Settings(ctx); got.Enabled {
		t.Errorf("an invalid schedule is on: %+v", got)
	}
}

func FuzzAutoSchedule(f *testing.F) {
	f.Add(true, 3, "03:00", "", int64(1763600000), "UTC")
	f.Add(true, 0, "23:59", "00:00", int64(0), "America/New_York")
	f.Add(false, 6, "02:30", "02:30", int64(-5e9), "Pacific/Auckland")
	f.Fuzz(func(t *testing.T, on bool, day int, t1, t2 string, unix int64, zone string) {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			loc = time.UTC
		}
		v, err := ValidateAuto(AutoSettings{Enabled: on, Days: []int{day}, Times: []string{t1, t2}})
		if err != nil {
			return
		}
		if again, err := ValidateAuto(v); err != nil || !reflect.DeepEqual(again, v) {
			t.Fatalf("validating twice changed %+v to %+v (%v)", v, again, err)
		}
		from := time.Unix(unix%(1<<35), 0)
		next := NextAuto(v, from, loc)
		if len(v.Times) == 0 {
			if !next.IsZero() {
				t.Fatalf("no times but next = %v", next)
			}
			return
		}
		if !next.After(from) || next.Sub(from) > 9*24*time.Hour {
			t.Fatalf("next %v from %v with %+v", next, from, v)
		}
		if len(v.Days) > 0 {
			ok := false
			for _, d := range v.Days {
				ok = ok || d == int(next.In(loc).Weekday())
			}
			if !ok {
				t.Fatalf("%v is not on one of the days %v", next, v.Days)
			}
		}
	})
}
