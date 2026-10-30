package search

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

func setup(t *testing.T) (*Engine, *storage.Repository) {
	t.Helper()
	db, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := storage.NewRepository(db)
	return NewEngine(repo), repo
}

func TestParseTerms(t *testing.T) {
	e, _ := setup(t)
	ctx := context.Background()
	type want struct {
		words  string
		conds  []storage.Cond
		threat bool
	}
	for in, w := range map[string]want{
		``:                                     {},
		`failed AND "invalid user"`:            {words: `failed AND "invalid user"`},
		`src_ip=10.0.0.1`:                      {conds: []storage.Cond{{Field: "src_ip", Values: []string{"10.0.0.1"}}}},
		`ip=192.168.48.20,192.168.48.21`:       {conds: []storage.Cond{{Field: "ip", Values: []string{"192.168.48.20", "192.168.48.21"}}}},
		`failed src_ip=1.1.1.1 dst_ip=2.2.2.2`: {words: "failed", conds: []storage.Cond{{Field: "src_ip", Values: []string{"1.1.1.1"}}, {Field: "dst_ip", Values: []string{"2.2.2.2"}}}},
		`failed AND src_ip=1.1.1.1`:            {words: "failed", conds: []storage.Cond{{Field: "src_ip", Values: []string{"1.1.1.1"}}}},
		`src_ip=1.1.1.1 AND failed`:            {words: "failed", conds: []storage.Cond{{Field: "src_ip", Values: []string{"1.1.1.1"}}}},
		`a AND src_ip=1.1.1.1 AND b`:           {words: "a AND b", conds: []storage.Cond{{Field: "src_ip", Values: []string{"1.1.1.1"}}}},
		`USER="Jonathan Martinez",bob`:         {conds: []storage.Cond{{Field: "user", Values: []string{"Jonathan Martinez", "bob"}}}},
		`"a=b" user=x`:                         {words: `"a=b"`, conds: []storage.Cond{{Field: "user", Values: []string{"x"}}}},
		`severity=high,critical,3`:             {conds: []storage.Cond{{Field: "severity", Values: []string{"4", "5", "3"}}}},
		`country=nl,de asn=AS15169`:            {conds: []storage.Cond{{Field: "country", Values: []string{"NL", "DE"}}, {Field: "asn", Values: []string{"15169"}}}},
		`threat=true`:                          {threat: true},
		`action=login meta.users="Ann B"`:      {conds: []storage.Cond{{Field: "action", Values: []string{"login"}}, {Field: "meta.users", Values: []string{"Ann B"}}}},
		`(src_ip=1.1.1.1)`:                     {words: `(src_ip=1.1.1.1)`},
	} {
		words, conds, threat, err := e.parseTerms(ctx, in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if words != w.words || !reflect.DeepEqual(conds, w.conds) && !(len(conds) == 0 && len(w.conds) == 0) || threat != w.threat {
			t.Errorf("%q = %q %+v %v, want %q %+v %v", in, words, conds, threat, w.words, w.conds, w.threat)
		}
	}
	for in, why := range map[string]string{
		`src_ip=`:                    "needs a value",
		`user="unclosed`:             "quote",
		`NOT user=bob`:               "NOT",
		`user=bob OR user=ann`:       "OR",
		`severity=loud`:              "1-6",
		`country=NLD`:                "two-letter",
		`asn=abc`:                    "number",
		`threat=maybe`:               "true or false",
		`source=nothing-called-this`: "no source",
	} {
		if _, _, _, err := e.parseTerms(ctx, in); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: error = %v, want one about %q", in, err, why)
		}
	}
}

// Field terms narrow a search the way the filter boxes do, and the words still work beside them.
func TestSearchWithFieldTerms(t *testing.T) {
	e, repo := setup(t)
	ctx := context.Background()
	src, err := repo.CreateTokenSource(ctx, "Firewall", "k", nil, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	mk := func(i int, src4 string, dst string, user string, sev int, msg string, fields string, sourceID int64) storage.Record {
		r := storage.Record{Timestamp: now - int64(i)*1000, CategoryUID: 3, ClassUID: 3002, SeverityID: sev, SrcIP: src4, DstIP: dst,
			UserName: user, Message: msg, RawData: msg, Host: "web1", SourceID: sourceID}
		if fields != "" {
			r.Fields = json.RawMessage(fields)
		}
		return r
	}
	if err := repo.InsertBatch(ctx, []storage.Record{
		mk(0, "192.168.48.20", "10.0.0.1", "alice", 3, "login failed", "", src),
		mk(1, "192.168.48.21", "10.0.0.2", "bob", 3, "login failed", "", 0),
		mk(2, "192.168.48.22", "10.0.0.1", "alice", 1, "login ok", "", src),
		mk(3, "10.9.9.9", "192.168.48.21", "carol", 5, "port scan", "", 0),
		mk(4, "", "", "system", 1, "Emailed digest", `{"action":"digest","meta.failed":"[]","meta.users":"[\"Jonathan Martinez\",\"Ann B\"]","id":1782}`, 0),
	}); err != nil {
		t.Fatal(err)
	}
	count := func(q string) int {
		t.Helper()
		res, err := e.Search(ctx, Query{Text: q, Limit: 100})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		return res.Count
	}
	for q, want := range map[string]int{
		`src_ip=192.168.48.20`:               1,
		`src_ip=192.168.48.20,192.168.48.21`: 2,
		`ip=192.168.48.21`:                   2, // as a source and as a destination
		`ip=192.168.48.20,192.168.48.21`:     3,
		`dst_ip=10.0.0.1`:                    2,
		`user=alice`:                         2,
		`user=alice,bob`:                     3,
		`user=alice severity=info`:           1,
		`user=alice,bob failed`:              2,
		`failed AND user=bob`:                1,
		`severity=high,critical`:             1,
		`host=web1`:                          5,
		`source=firewall`:                    2,
		`source=Firewall,internal`:           2,
		`action=digest`:                      1,
		`action=digest,login`:                1,
		`id=1782`:                            1,
		`meta.users="Jonathan Martinez"`:     1,
		`meta.users="Ann B"`:                 1,
		`meta.users="Nobody"`:                0,
		`action=nope`:                        0,
		`failed`:                             2, // the field named failed on the digest doesn't count
		`jonathan`:                           1, // its value does
		`threat=true`:                        0,
		`src_ip=192.168.48.20 user=bob`:      0,
	} {
		if got := count(q); got != want {
			t.Errorf("%q found %d events, want %d", q, got, want)
		}
	}
	// Terms combine with the filter boxes (both apply).
	res, err := e.Search(ctx, Query{Text: `user=alice,bob`, SrcIP: "192.168.48.21", Limit: 10})
	if err != nil || res.Count != 1 {
		t.Errorf("a term and a filter box = %v %v", res, err)
	}
	// The old error for an unknown "=" is gone; a real mistake still is one.
	if _, err := e.Search(ctx, Query{Text: `"unterminated`}); err == nil {
		t.Error("a broken phrase should still be an invalid query")
	}
}
