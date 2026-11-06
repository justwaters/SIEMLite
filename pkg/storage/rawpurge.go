package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// RawKeep is how long an event's original line is kept after it arrives,
// unless the System page says otherwise (see RawKeepHours). The parsed event
// (message, fields, addresses) is kept for the whole retention period, and is
// what search covers.
const RawKeep = 24 * time.Hour

const (
	// RawKeepSetting holds the number of hours original lines are kept; 0 keeps them as long as the event.
	RawKeepSetting = "raw_keep_hours"
	// MaxRawKeepHours is the longest an original line can be asked to be kept: ten years.
	MaxRawKeepHours = 3650 * 24
)

// RawKeepHours is how many hours an original line is kept after it arrives:
// the saved setting, else 24. 0 means never remove it.
func (r *Repository) RawKeepHours(ctx context.Context) (hours int, saved bool, err error) {
	text, err := r.Setting(ctx, RawKeepSetting, "")
	if err != nil {
		return 0, false, err
	}
	if text == "" {
		return int(RawKeep / time.Hour), false, nil
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 0 || n > MaxRawKeepHours {
		return int(RawKeep / time.Hour), false, nil
	}
	return n, true, nil
}

// SetRawKeepHours saves how many hours original lines are kept (0 = always).
func (r *Repository) SetRawKeepHours(ctx context.Context, hours int) error {
	if hours < 0 || hours > MaxRawKeepHours {
		return fmt.Errorf("keep original lines between 0 and %d hours", MaxRawKeepHours)
	}
	return r.SetSetting(ctx, RawKeepSetting, strconv.Itoa(hours))
}

const (
	rawWatermarksKey = "raw_watermarks" // JSON list of watermarks, oldest first
	rawPurgedKey     = "raw_purged_seq" // original lines are gone for every event up to this arrival number
	rawPurgeBatch    = 5000             // rows cleared per transaction, so storing isn't starved
)

// thinWatermarks keeps one watermark a day, and the newest, and drops those
// older than the longest a line can be kept, so the list stays small however
// long lines are kept forever.
func thinWatermarks(marks []watermark, nowMs int64) []watermark {
	const day = int64(24 * time.Hour / time.Millisecond)
	oldest := nowMs - int64(MaxRawKeepHours)*int64(time.Hour/time.Millisecond)
	var out []watermark
	for i, m := range marks {
		if m.At < oldest {
			continue
		}
		if i == len(marks)-1 || len(out) == 0 || m.At-out[len(out)-1].At >= day {
			out = append(out, m)
		}
	}
	return out
}

// watermark says that at a time (unix ms) every event up to arrival number
// seq had been stored.
type watermark struct {
	At  int64 `json:"at"`
	Seq int64 `json:"seq"`
}

// PurgeRawLines removes the original line of every event that arrived at
// least the kept time (RawKeepHours, 24 by default) before now, and returns how many it cleared. It goes by
// arrival, not by the event's own time, so a late or back-dated event keeps
// its line for the same day as any other. Arrival numbers (seq) only say what
// came before what, so each call records how far they had got (a watermark);
// a line is removed once a watermark at least that old covers it. Call it
// about hourly; it is safe to call more often or twice. Events still in the
// main database waiting to be moved are left alone: they are moved with their
// original line and cleared here once they are in a day file.
func (r *Repository) PurgeRawLines(ctx context.Context, now time.Time) (int64, error) {
	d := r.db.days
	hours, _, err := r.RawKeepHours(ctx)
	if err != nil {
		return 0, err
	}
	keep := time.Duration(hours) * time.Hour
	text, err := r.Setting(ctx, rawWatermarksKey, "[]")
	if err != nil {
		return 0, err
	}
	var marks []watermark
	if err := json.Unmarshal([]byte(text), &marks); err != nil {
		marks = nil // damaged: start the history again
	}
	nowMs := now.UnixMilli()
	marks = append(marks, watermark{At: nowMs, Seq: d.seq.Load()})
	if hours == 0 {
		// Lines are kept as long as their events, so nothing is removed. The
		// watermarks are still recorded, a day apart, so that choosing a time
		// later removes the lines older than it at once, not a day later.
		b, _ := json.Marshal(thinWatermarks(marks, nowMs))
		return 0, r.SetSetting(ctx, rawWatermarksKey, string(b))
	}
	// The newest watermark old enough is the one to purge up to; older ones
	// are no longer needed.
	target := -1
	for i, m := range marks {
		if m.At <= nowMs-keep.Milliseconds() {
			target = i
		}
	}
	if target > 0 {
		marks = marks[target:]
	}
	b, _ := json.Marshal(marks)
	if err := r.SetSetting(ctx, rawWatermarksKey, string(b)); err != nil {
		return 0, err
	}
	if target < 0 {
		return 0, nil
	}
	upTo := marks[0].Seq
	text, err = r.Setting(ctx, rawPurgedKey, "0")
	if err != nil {
		return 0, err
	}
	var from int64
	fmt.Sscan(text, &from)
	if upTo <= from {
		return 0, nil
	}

	var total int64
	d.move.RLock()
	shards := d.span(0, 0)
	d.move.RUnlock()
	for _, s := range shards {
		if s.day == 0 {
			continue
		}
		n, err := d.purgeShard(ctx, s, from, upTo)
		total += n
		if err != nil {
			return total, err
		}
	}
	if err := r.SetSetting(ctx, rawPurgedKey, fmt.Sprint(upTo)); err != nil {
		return total, err
	}
	return total, nil
}

// purgeShard clears the original line of events in a day whose arrival
// number is in (from, upTo], a batch at a time. The seq index makes a day
// with nothing in that range cost almost nothing.
func (d *days) purgeShard(ctx context.Context, s *shard, from, upTo int64) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		// Hold off whole-day deletes while writing, so a removed day's file
		// is never created again.
		d.move.RLock()
		if d.shard(s.day, false) == nil {
			d.move.RUnlock()
			return total, nil
		}
		w, err := s.writer(ctx)
		if err != nil {
			d.move.RUnlock()
			return total, err
		}
		res, err := w.ExecContext(ctx, `UPDATE events SET raw_data = '' WHERE id IN
			(SELECT id FROM events WHERE seq > ? AND seq <= ? AND raw_data <> '' LIMIT ?)`, from, upTo, rawPurgeBatch)
		d.move.RUnlock()
		if err != nil {
			return total, fmt.Errorf("remove original lines in %s: %w", dayName(s.day), err)
		}
		n, _ := res.RowsAffected()
		total += n
		if n < rawPurgeBatch {
			return total, nil
		}
	}
}
