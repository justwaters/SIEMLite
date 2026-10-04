package backup

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzBackupName: only plain backup file names are accepted, so a name from
// a URL can never point outside the backup folder.
func FuzzBackupName(f *testing.F) {
	for _, s := range []string{
		"siemlite-20261003-101712-manual.db.gz", "siemlite-20261003-101712-2-auto.db.gz",
		"../siemlite-20261003-101712-manual.db.gz", "siemlite-20261399-101712-manual.db.gz",
		"siemlite-20261003-101712-manual.db.gz/..", "siemlite-20261003-101712-uploaded.db.gz\x00.txt",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		b, ok := parse(name)
		if !ok {
			return
		}
		if strings.ContainsAny(name, `/\`+"\x00") || name != filepath.Base(name) || filepath.Clean(name) != name {
			t.Fatalf("accepted unsafe name %q", name)
		}
		if b.Name != name || (b.Kind != "manual" && b.Kind != "auto" && b.Kind != "before-restore" && b.Kind != "uploaded") {
			t.Fatalf("parsed %q as %+v", name, b)
		}
	})
}
