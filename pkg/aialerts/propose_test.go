package aialerts

import (
	"fmt"
	"strings"
	"testing"

	"siemlite/pkg/storage"
)

func TestShapeGroupsSimilarMessages(t *testing.T) {
	a := shape("Accepted password for jo from 10.1.2.3 port 5022 ssh2 session 3f9a8b7c6d5e")
	b := shape("Accepted password for jo from 192.168.0.9 port 61000 ssh2 session aabbccddeeff00")
	if a != b || !strings.Contains(a, "<ip>") || !strings.Contains(a, "port #") {
		t.Errorf("shapes differ: %q vs %q", a, b)
	}
	if shape("Accepted password for al") == a {
		t.Error("different messages share a shape")
	}
}

// A digest stays small however many kinds of message there are, keeps the
// serious rare ones, and leaves out lines with nothing in them.
func TestDigestIsBoundedAndKeepsTheSerious(t *testing.T) {
	var events []storage.Record
	for i := 0; i < 3000; i++ {
		events = append(events, storage.Record{SeverityID: 1, Source: "app", Message: fmt.Sprintf("routine kind %c%c%c happened", 'a'+i%26, 'a'+(i/26)%26, 'a'+(i/676)%26)})
	}
	events = append(events, storage.Record{SeverityID: 5, Source: "app", UserName: "root", SrcIP: "10.0.0.9", Message: "privilege escalation by root"})
	d := digest(events)
	if len(d) > maxDigestLen+400 {
		t.Errorf("digest is %d characters", len(d))
	}
	if !strings.Contains(d, "privilege escalation by root") || !strings.Contains(d, "3001 events") {
		t.Errorf("digest = %s", d)
	}
	if strings.Contains(d, "Hosts:") {
		t.Error("a line with nothing in it was kept")
	}
}
