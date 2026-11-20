package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestReportScheduleCRUD(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	s := ReportSchedule{Name: "Weekly", Frequency: "weekly", Weekday: 1, Hour: 8, CoversDays: 7, Recipients: "a@x.io,b@x.io", Enabled: true, NextRun: 1000}
	id, err := repo.CreateReportSchedule(ctx, s, 50)
	if err != nil || id == 0 {
		t.Fatal(id, err)
	}
	got, err := repo.GetReportSchedule(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	s.ID, s.CreatedAt = id, 50
	if got != s {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, s)
	}
	if got.LastRun != 0 || got.LastStatus != "" {
		t.Errorf("fresh schedule has a last run: %+v", got)
	}
	if _, err := repo.GetReportSchedule(ctx, 777); !errors.Is(err, ErrReportNotFound) {
		t.Errorf("get unknown: %v", err)
	}

	s.Name, s.Enabled, s.Frequency, s.DayOfMonth, s.NextRun = "monthly", false, "monthly", 15, 5000
	if err := repo.UpdateReportSchedule(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetReportSchedule(ctx, id)
	if got.Name != "monthly" || got.Enabled || got.Frequency != "monthly" || got.DayOfMonth != 15 || got.NextRun != 5000 || got.CreatedAt != 50 {
		t.Errorf("after update: %+v", got)
	}
	if err := repo.UpdateReportSchedule(ctx, ReportSchedule{ID: 777}); !errors.Is(err, ErrReportNotFound) {
		t.Errorf("update unknown: %v", err)
	}

	id2, _ := repo.CreateReportSchedule(ctx, ReportSchedule{Name: "Alpha", Frequency: "daily"}, 60)
	list, err := repo.ReportSchedules(ctx)
	if err != nil || len(list) != 2 || list[0].ID != id2 || list[1].ID != id {
		t.Errorf("schedules should be ordered by name (Alpha, monthly): %+v %v", list, err)
	}
}

func TestDueReportSchedules(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	mk := func(name string, en bool, next int64) int64 {
		id, err := repo.CreateReportSchedule(ctx, ReportSchedule{Name: name, Frequency: "daily", Enabled: en, NextRun: next}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	past := mk("past", true, 100)
	exact := mk("exact", true, 500)
	mk("future", true, 501)
	mk("disabled", false, 1)
	earlier := mk("earlier", true, 50)

	due, err := repo.DueReportSchedules(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 3 || due[0].ID != earlier || due[1].ID != past || due[2].ID != exact {
		t.Fatalf("due = %+v, want earlier, past, exact in next_run order", due)
	}
	if d, _ := repo.DueReportSchedules(ctx, 0); len(d) != 0 {
		t.Errorf("nothing is due at 0: %+v", d)
	}

	// Marking a run records it and pushes the next run out.
	if err := repo.MarkReportScheduleRan(ctx, past, 500, 9999, "sent"); err != nil {
		t.Fatal(err)
	}
	s, _ := repo.GetReportSchedule(ctx, past)
	if s.LastRun != 500 || s.NextRun != 9999 || s.LastStatus != "sent" {
		t.Errorf("after mark: %+v", s)
	}
	due, _ = repo.DueReportSchedules(ctx, 500)
	for _, d := range due {
		if d.ID == past {
			t.Error("a schedule that just ran is still due")
		}
	}
}

func TestReportRunsPruneAndDelivery(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	sid, _ := repo.CreateReportSchedule(ctx, ReportSchedule{Name: "s", Frequency: "daily", Enabled: true}, 1)

	total := MaxReportRuns + 5
	ids := make([]int64, total)
	for i := 0; i < total; i++ {
		run := ReportRun{Name: "r", Trigger: "manual", CreatedAt: int64(1000 + i), PeriodStart: 1, PeriodEnd: 2, PDF: []byte("pdf")}
		id, err := repo.AddReportRun(ctx, run)
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	runs, err := repo.ReportRuns(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != MaxReportRuns {
		t.Fatalf("kept %d runs, want %d", len(runs), MaxReportRuns)
	}
	if runs[0].ID != ids[total-1] || runs[len(runs)-1].ID != ids[5] {
		t.Errorf("pruning should keep the newest: first=%d last=%d", runs[0].ID, runs[len(runs)-1].ID)
	}
	if _, err := repo.GetReportRun(ctx, ids[0]); !errors.Is(err, ErrReportNotFound) {
		t.Errorf("oldest run should be gone: %v", err)
	}
	if lim, _ := repo.ReportRuns(ctx, 3); len(lim) != 3 || lim[0].ID != ids[total-1] {
		t.Errorf("limit: %+v", lim)
	}

	// Full record, with the PDF, size, schedule link and delivery.
	pdf := []byte("%PDF-1.7\x00\x01binary")
	rid, err := repo.AddReportRun(ctx, ReportRun{ScheduleID: &sid, Name: "Weekly", Trigger: "schedule", CreatedAt: 99999, PeriodStart: 10, PeriodEnd: 20, PDF: pdf})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetReportRunDelivery(ctx, rid, "a@x.io", "partial"); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetReportRun(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.PDF, pdf) || got.Size != int64(len(pdf)) || got.Emailed != "a@x.io" || got.Note != "partial" ||
		got.Trigger != "schedule" || got.PeriodStart != 10 || got.PeriodEnd != 20 || got.ScheduleID == nil || *got.ScheduleID != sid {
		t.Errorf("run: %+v", got)
	}
	list, _ := repo.ReportRuns(ctx, 1)
	if len(list) != 1 || list[0].ID != rid || list[0].PDF != nil || list[0].Size != int64(len(pdf)) {
		t.Errorf("listing should not load PDFs: %+v", list)
	}

	// Deleting the schedule keeps its runs but unlinks them.
	if _, err := repo.DeleteReportSchedule(ctx, sid); err != nil {
		t.Fatal(err)
	}
	got, err = repo.GetReportRun(ctx, rid)
	if err != nil || got.ScheduleID != nil || !bytes.Equal(got.PDF, pdf) {
		t.Errorf("run after its schedule was deleted: %+v %v", got, err)
	}
	if _, err := repo.DeleteReportSchedule(ctx, sid); !errors.Is(err, ErrReportNotFound) {
		t.Errorf("delete twice: %v", err)
	}

	if err := repo.DeleteReportRun(ctx, rid); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteReportRun(ctx, rid); !errors.Is(err, ErrReportNotFound) {
		t.Errorf("delete run twice: %v", err)
	}
}

func TestDeleteReportScheduleName(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	id, _ := repo.CreateReportSchedule(ctx, ReportSchedule{Name: "Nightly", Frequency: "daily"}, 1)
	if name, err := repo.DeleteReportSchedule(ctx, id); err != nil || name != "Nightly" {
		t.Errorf("%q %v", name, err)
	}
	if l, _ := repo.ReportSchedules(ctx); len(l) != 0 {
		t.Errorf("still listed: %+v", l)
	}
}
