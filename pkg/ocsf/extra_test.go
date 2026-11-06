package ocsf

import (
	"fmt"
	"strings"
	"testing"
)

func TestExtraFieldsFlattenAndCap(t *testing.T) {
	ev := &Event{Unmapped: map[string]any{
		"id": float64(2332), "ok": true, "gone": nil,
		"meta": map[string]any{"reason": "Per chat", "n": map[string]any{"deep": "x"}},
		"list": []any{"a", float64(1)},
	}}
	got := ev.ExtraFields()
	want := map[string]string{"id": "2332", "ok": "true", "meta.reason": "Per chat", "meta.n.deep": "x", "list": `["a",1]`}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if (&Event{}).ExtraFields() != nil {
		t.Error("no unmapped values should give none")
	}

	big := map[string]any{"long": strings.Repeat("x", 5000)}
	for i := 0; i < 150; i++ {
		big[fmt.Sprintf("k%03d", i)] = "v"
	}
	f := (&Event{Unmapped: big}).ExtraFields()
	if len(f) != maxExtraFields || len(f["k000"]) != 1 {
		t.Fatalf("%d values kept", len(f))
	}
	if _, ok := f["long"]; ok { // "long" sorts after k000..k098, so the cap drops it, the same way every time
		t.Error("the cap should keep the first keys in sorted order")
	}
	if l := (&Event{Unmapped: map[string]any{"long": strings.Repeat("x", 5000)}}).ExtraFields()["long"]; len(l) != maxExtraFieldLen {
		t.Errorf("long value is %d bytes", len(l))
	}
}
