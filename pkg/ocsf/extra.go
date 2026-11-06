package ocsf

import (
	"encoding/json"
	"sort"
	"strconv"
)

// Limits on the values ExtraFields keeps from one event. They are generous
// because the original line is removed after a while, and what is not kept
// here is lost with it. The walk itself is bounded too: a hostile line can't
// make it build more than this, however it is nested.
const (
	maxExtraFields   = 100
	maxExtraFieldLen = 2048
	maxExtraKeyLen   = 256 // a longer dotted name is skipped
	maxExtraDepth    = 8   // objects nested deeper are kept as their JSON
)

// ExtraFields returns the values in Unmapped as flat text, nested objects
// as dotted names ("meta.reason"), so they can be stored and searched with
// the event. Keys are taken in sorted order, so when there are more than
// maxExtraFields the same ones are kept every time.
func (e *Event) ExtraFields() map[string]string {
	if len(e.Unmapped) == 0 {
		return nil
	}
	w := &walk{out: map[string]string{}, skip: nil}
	w.value("", e.Unmapped, 0)
	if len(w.out) == 0 {
		return nil
	}
	return w.out
}

// FlattenJSON flattens a decoded JSON object into dotted names and text
// values, for Event.Unmapped, leaving out the named dotted keys. It keeps at
// most maxExtraFields values, each cut at maxExtraFieldLen.
func FlattenJSON(obj map[string]any, skip ...string) map[string]any {
	w := &walk{out: map[string]string{}, skip: map[string]bool{}}
	for _, k := range skip {
		w.skip[k] = true
	}
	w.value("", obj, 0)
	out := make(map[string]any, len(w.out))
	for k, v := range w.out {
		out[k] = v
	}
	return out
}

// walk collects flat values and stops as soon as it has enough.
type walk struct {
	out  map[string]string
	skip map[string]bool
}

func (w *walk) full() bool { return len(w.out) >= maxExtraFields }

func (w *walk) put(k, v string) {
	if k == "" || len(k) > maxExtraKeyLen || w.skip[k] || w.full() {
		return
	}
	if len(v) > maxExtraFieldLen {
		v = v[:maxExtraFieldLen]
	}
	w.out[k] = v
}

func (w *walk) value(prefix string, v any, depth int) {
	if w.full() {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		if depth >= maxExtraDepth {
			b, _ := json.Marshal(x)
			w.put(prefix, string(b))
			return
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if w.full() {
				return
			}
			key := k
			if prefix != "" {
				if len(prefix)+1+len(k) > maxExtraKeyLen {
					continue
				}
				key = prefix + "." + k
			}
			w.value(key, x[k], depth+1)
		}
	case nil:
	case string:
		w.put(prefix, x)
	case float64:
		w.put(prefix, strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		w.put(prefix, strconv.FormatBool(x))
	default:
		b, _ := json.Marshal(x)
		w.put(prefix, string(b))
	}
}
