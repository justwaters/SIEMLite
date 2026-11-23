package storage

import "testing"

// When the source names can't be read, a source group is shown as "source <id>", not as a deleted source.
func TestSourceGroupLabel(t *testing.T) {
	if got := sourceGroupLabel(nil, "7"); got != "source 7" {
		t.Errorf("names unavailable: %q", got)
	}
	if got := sourceGroupLabel(map[int64]string{7: "web"}, "7"); got != "web" {
		t.Errorf("known source: %q", got)
	}
	if got := sourceGroupLabel(map[int64]string{}, "7"); got != "Deleted source" {
		t.Errorf("deleted source: %q", got)
	}
}
