package parser

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestJSONTimestampForms(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		`{"time":"2024-01-02 03:04:05Z","msg":"x"}`:      "2024-01-02T03:04:05Z",
		`{"time":"2024-01-02T03:04:05+0100","msg":"x"}`:  "2024-01-02T02:04:05Z",
		`{"ts":1700000000.5,"msg":"x"}`:                  "2023-11-14T22:13:20Z",
		`{"time":1700000000000,"msg":"x"}`:               "2023-11-14T22:13:20Z",
		`{"time":"2024-01-02 03:04:05+01:00","msg":"x"}`: "2024-01-02T02:04:05Z",
	} {
		ev := ParseLine(in, Defaults{Now: now})
		if got := time.UnixMilli(ev.Time).UTC().Format(time.RFC3339); got != want {
			t.Errorf("%s: time = %s, want %s", in, got, want)
		}
	}
}

func TestCaptureGroupInPlaceholderRegex(t *testing.T) {
	re, names, err := CompilePattern(`{a:(x|y)} {user} from {src_ip}`)
	if err != nil {
		t.Fatal(err)
	}
	m := re.FindStringSubmatch("x bob from 1.2.3.4")
	if len(m) != len(names)+1 || m[2] != "bob" || m[3] != "1.2.3.4" {
		t.Errorf("groups = %q for names %v", m, names)
	}
}

func TestCutUTF8(t *testing.T) {
	s := strings.Repeat("é", 10) // two bytes each
	if got := cutUTF8(s, 5); !utf8.ValidString(got) || len(got) != 4 {
		t.Errorf("cutUTF8 = %q (%d bytes)", got, len(got))
	}
}
