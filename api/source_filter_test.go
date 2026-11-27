package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"siemlite/pkg/auth"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

// Setup for the source filter tests: four sources, each with one event whose
// message names it, an admin and a standard user limited to sources 2 and 3.
type sourceFilterEnv struct {
	*env
	root, sam *http.Client
	ids       []int64 // the four source ids, in order
}

func newSourceFilterEnv(t *testing.T) *sourceFilterEnv {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	f := &sourceFilterEnv{env: e, root: root}
	for _, name := range []string{"alpha", "beta", "gamma", "delta"} {
		var res struct {
			Source storage.Source `json:"source"`
			Token  string         `json:"token"`
		}
		if got := e.call(root, "POST", "/api/v1/sources", map[string]any{"name": name}, &res, nil); got != 201 {
			t.Fatalf("create %s = %d", name, got)
		}
		expect(t, "send "+name, e.do(e.client(), "POST", "/api/v1/logs", "multimark from "+name,
			map[string]string{"Authorization": "Bearer " + res.Token}), 202)
		f.ids = append(f.ids, res.Source.ID)
	}
	e.worker.Drain(context.Background())
	if got := e.call(root, "POST", "/api/v1/users", map[string]any{
		"username": "sam", "password": password, "role": "standard", "sources": []int64{f.ids[1], f.ids[2]}}, nil, nil); got != 201 {
		t.Fatalf("create sam = %d", got)
	}
	f.sam = e.client()
	e.login(f.sam, "sam", password)
	return f
}

// names runs a search as c and returns the sorted source names of the events.
func (f *sourceFilterEnv) names(c *http.Client, query string) ([]string, int) {
	f.t.Helper()
	var res search.Result
	code := f.call(c, "GET", "/api/v1/search?limit=1000&q=multimark&"+query, nil, &res, nil)
	var out []string
	for _, ev := range res.Events {
		out = append(out, ev.SourceName)
	}
	sort.Strings(out)
	return out, code
}

func TestSearchSourceIDsUnionAndForms(t *testing.T) {
	f := newSourceFilterEnv(t)
	a, b, c, d := f.ids[0], f.ids[1], f.ids[2], f.ids[3]
	for _, tc := range []struct {
		name, query string
		want        string
	}{
		{"single value still works", fmt.Sprintf("source_id=%d", b), "beta"},
		{"repeated parameter", fmt.Sprintf("source_id=%d&source_id=%d", a, d), "alpha delta"},
		{"comma list", fmt.Sprintf("source_id=%d,%d", a, c), "alpha gamma"},
		{"comma list and repeats mixed, with a duplicate", fmt.Sprintf("source_id=%d,%d&source_id=%d", a, b, a), "alpha beta"},
		{"spaces and a trailing comma", fmt.Sprintf("source_id=%d,%%20%d,", b, c), "beta gamma"},
		{"zero means any, as before", "source_id=0", "alpha beta delta gamma"},
		{"none", "", "alpha beta delta gamma"},
	} {
		got, code := f.names(f.root, tc.query)
		if code != 200 || strings.Join(got, " ") != tc.want {
			t.Errorf("%s: %d %v, want %s", tc.name, code, got, tc.want)
		}
	}
}

func TestSearchSourceIDsIntersectWithRestriction(t *testing.T) {
	f := newSourceFilterEnv(t)
	a, b, c := f.ids[0], f.ids[1], f.ids[2]
	for _, tc := range []struct {
		name, query string
		want        string
	}{
		{"no filter shows only the allowed sources", "", "beta gamma"},
		{"asking for one allowed and one forbidden", fmt.Sprintf("source_id=%d,%d", a, b), "beta"},
		{"both allowed", fmt.Sprintf("source_id=%d&source_id=%d", b, c), "beta gamma"},
		{"only forbidden ones", fmt.Sprintf("source_id=%d,%d", a, f.ids[3]), ""},
		{"a forbidden single id", fmt.Sprintf("source_id=%d", a), ""},
	} {
		got, code := f.names(f.sam, tc.query)
		if code != 200 || strings.Join(got, " ") != tc.want {
			t.Errorf("%s: %d %v, want %q", tc.name, code, got, tc.want)
		}
	}
}

func TestSearchSourceIDsBadValues(t *testing.T) {
	f := newSourceFilterEnv(t)
	tooMany := make([]string, 201)
	for i := range tooMany {
		tooMany[i] = fmt.Sprint(i + 1)
	}
	atCap := strings.Join(tooMany[:200], ",")
	for _, tc := range []struct {
		name  string
		query string
		code  int
	}{
		{"not a number", "source_id=abc", 400},
		{"one bad in a list", "source_id=1,x,3", 400},
		{"negative", "source_id=-4", 400},
		{"a decimal", "source_id=1.5", 400},
		{"the cap", "source_id=" + atCap, 200},
		{"over the cap", "source_id=" + strings.Join(tooMany, ","), 400},
		{"over the cap across repeats", "source_id=" + url.QueryEscape(atCap) + "&source_id=999", 400},
	} {
		if _, code := f.names(f.root, tc.query); code != tc.code {
			t.Errorf("%s: status %d, want %d", tc.name, code, tc.code)
		}
	}
}

func TestMCPSearchSourceIDs(t *testing.T) {
	f := newSourceFilterEnv(t)
	read := f.mcpToken(f.root, "multi", "read")
	count := func(args map[string]any) (map[string]bool, bool) {
		args["q"], args["limit"] = "multimark", 50
		text, isErr := f.tool(read, "search_events", args)
		got := map[string]bool{}
		for _, n := range []string{"alpha", "beta", "gamma", "delta"} {
			if strings.Contains(text, "multimark from "+n) {
				got[n] = true
			}
		}
		return got, isErr
	}
	if got, isErr := count(map[string]any{"source_id": f.ids[1]}); isErr || len(got) != 1 || !got["beta"] {
		t.Errorf("one id: %v %v", got, isErr)
	}
	if got, isErr := count(map[string]any{"source_id": []int64{f.ids[0], f.ids[3]}}); isErr || len(got) != 2 || !got["alpha"] || !got["delta"] {
		t.Errorf("an array: %v %v", got, isErr)
	}
	if got, isErr := count(map[string]any{}); isErr || len(got) != 4 {
		t.Errorf("no filter: %v %v", got, isErr)
	}
	if _, isErr := count(map[string]any{"source_id": "beta"}); !isErr {
		t.Error("a name for source_id was accepted")
	}
	if _, isErr := count(map[string]any{"source_id": []string{"x"}}); !isErr {
		t.Error("a non-numeric array was accepted")
	}
}
