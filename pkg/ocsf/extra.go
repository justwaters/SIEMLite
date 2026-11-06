package ocsf

import (
	"encoding/json"
	"sort"
	"strconv"
)

// Limits on the values ExtraFields keeps from one event. They are generous
// because the original line is removed after a while, and what is not kept
// here is lost with it.
const (
	maxExtraFields   = 100
	maxExtraFieldLen = 2048
)

// ExtraFields returns the values in Unmapped as flat text, nested objects
// as dotted names ("meta.reason"), so they can be stored and searched with
// the event. Keys are taken in sorted order, so when there are more than
// maxExtraFields the same ones are kept every time.
func (e *Event) ExtraFields() map[string]string {
	if len(e.Unmapped) == 0 {
		return nil
	}
	out := map[string]string{}
	put := func(k, v string) {
		if k == "" || len(out) >= maxExtraFields {
			return
		}
		if len(v) > maxExtraFieldLen {
			v = v[:maxExtraFieldLen]
		}
		out[k] = v
	}
	flattenValue("", e.Unmapped, put)
	if len(out) == 0 {
		return nil
	}
	return out
}

// FlattenJSON flattens a decoded JSON object into dotted names and text
// values, for Event.Unmapped. A list or other value that isn't text, a number
// or a flag is kept as its JSON.
func FlattenJSON(obj map[string]any) map[string]any {
	out := map[string]any{}
	flattenValue("", obj, func(k, v string) { out[k] = v })
	return out
}

func flattenValue(prefix string, v any, put func(k, v string)) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenValue(key, x[k], put)
		}
	case nil:
	case string:
		put(prefix, x)
	case float64:
		put(prefix, strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		put(prefix, strconv.FormatBool(x))
	default:
		b, _ := json.Marshal(x)
		put(prefix, string(b))
	}
}
