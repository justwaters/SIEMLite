package update

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// In a container the program file belongs to the image, so an update can't
// replace it. Instead the update is saved as <data>/bin/siemlite, and the
// image's program hands over to it when it starts:
//
//	<data>/bin/siemlite   the newer program
//	<data>/bin/version    its release, e.g. v0.9.2
//	<data>/bin/attempts   how many starts have handed over without it coming up
//
// The saved copy is dropped once the image is as new (after a rebuild or a
// pull), and if it hasn't come up healthy after two starts, so a bad update
// can't leave the container unable to start.

const maxAttempts = 2

func binDir(dataDir string) string { return filepath.Join(dataDir, "bin") }

// OverridePath is where a container's saved update lives.
func OverridePath(dataDir string) string { return filepath.Join(binDir(dataDir), "siemlite") }

func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// saveOverride moves the downloaded program at next into place as the saved
// update for release tag.
func saveOverride(dataDir, next, tag string) error {
	dir := binDir(dataDir)
	// Neither the version nor the count may outlive a program they don't describe.
	os.Remove(filepath.Join(dir, "version"))
	os.Remove(filepath.Join(dir, "attempts"))
	if err := os.Rename(next, OverridePath(dataDir)); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "version"), []byte(tag+"\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "attempts"), []byte("0\n"), 0o644)
}

func same(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}

// Override says which saved program should run in place of this one (release
// current, running from self), or "" to carry on as this one. A non-empty
// note explains a saved update that was dropped. Calling it counts as one
// handover attempt until MarkHealthy.
func Override(dataDir, current, self string) (path, note string) {
	bin := OverridePath(dataDir)
	if _, err := os.Stat(bin); err != nil || same(self, bin) {
		return "", "" // nothing saved, or this already is the saved update
	}
	drop := func(why string) (string, string) {
		os.RemoveAll(binDir(dataDir))
		return "", why
	}
	if !Newer(read(filepath.Join(binDir(dataDir), "version")), current) {
		return drop("the saved update is not newer than this version, so it was removed")
	}
	n, _ := strconv.Atoi(read(filepath.Join(binDir(dataDir), "attempts")))
	if n >= maxAttempts {
		return drop("the saved update did not start, so it was removed and this version is running")
	}
	if err := os.WriteFile(filepath.Join(binDir(dataDir), "attempts"), []byte(strconv.Itoa(n+1)+"\n"), 0o644); err != nil {
		return "", "" // can't track attempts, so don't risk a loop
	}
	return bin, ""
}

// MarkHealthy tells the next start that the program that just came up works.
func MarkHealthy(dataDir string) {
	os.Remove(filepath.Join(binDir(dataDir), "attempts"))
}
