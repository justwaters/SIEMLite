package api_test

import (
	"testing"

	"siemlite/pkg/auth"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
)

func TestParserSeverityDefaults(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	root, ann := e.client(), e.client()
	e.login(root, "root", password)
	e.login(ann, "ann", password)

	var rules []parser.SeverityCase
	if got := e.call(root, "GET", "/api/v1/parsers/severity-defaults", nil, &rules, nil); got != 200 {
		t.Fatalf("defaults = %d", got)
	}
	if len(rules) == 0 || rules[0].Severity != ocsf.SeverityCritical || rules[len(rules)-1].Match != "." {
		t.Errorf("rules = %+v, want worst first and a catch-all last", rules)
	}
	for _, r := range rules {
		if r.Severity == ocsf.SeverityFatal {
			t.Errorf("a default rule uses Fatal: %+v", r)
		}
	}
	if got := e.call(ann, "GET", "/api/v1/parsers/severity-defaults", nil, nil, nil); got != 403 {
		t.Errorf("a standard user got %d, want 403", got)
	}
}
