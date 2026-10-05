package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEmbeddedFindsShippedRules(t *testing.T) {
	rs, errs := LoadEmbedded()
	if len(errs) > 0 {
		t.Fatalf("embedded rules must parse cleanly: %v", errs)
	}
	if len(rs) == 0 {
		t.Fatal("no embedded rules; the binary would be useless")
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" {
			t.Errorf("rule %q has no title", r.ID)
		}
		if len(r.Detect.Checks) == 0 {
			t.Errorf("rule %q has no checks; it can never detect anything", r.ID)
		}
		if r.Blame.Subject.Kind == "" {
			t.Errorf("rule %q has no blame subject; it can never attribute", r.ID)
		}
	}
}

// Every rule must be reachable from `why`. A rule nobody can match is dead
// weight in the binary.
func TestEveryRuleIsReachableByQuery(t *testing.T) {
	rs, _ := LoadEmbedded()
	for _, r := range rs {
		if len(r.Symptom) == 0 && r.ID == "" {
			t.Errorf("rule %q has neither symptoms nor an id", r.ID)
		}
		if !r.Matches(r.ID) {
			t.Errorf("rule %q cannot be reached by its own id", r.ID)
		}
	}
}

func TestMatchesIsCaseInsensitiveAndSubstringBased(t *testing.T) {
	r := &Rule{ID: "demo", Symptom: []string{"26H2", "feature update"}}
	cases := map[string]bool{
		"26h2 not offered":  true,
		"26H2":              true,
		"no feature update": true,
		"printer broken":    false,
		"":                  false,
	}
	for query, want := range cases {
		if got := r.Matches(query); got != want {
			t.Errorf("Matches(%q) = %v, want %v", query, got, want)
		}
	}
}

// A malformed file must be reported, and must not stop the other files from
// loading. A user running a diagnosis right now should not lose every rule
// because one of them has a typo.
func TestBadRuleDoesNotBlockOthers(t *testing.T) {
	dir := t.TempDir()
	good := "id: good-rule\ntitle: good\ndetect:\n  kind: registry\n"
	bad := "id: bad-rule\n  : broken yaml : ["
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, errs := Load(dir)
	if len(rs) != 1 {
		t.Fatalf("loaded %d rules, want 1 (the good one)", len(rs))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
	if !strings.Contains(errs[0].Error(), "bad.yaml") {
		t.Errorf("error should name the offending file, got %v", errs[0])
	}
}

func TestLoadSkipsUnderscoreAndNonYamlFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"_template.yaml": "id: template",
		"notes.txt":      "id: should-not-load",
		"real.yml":       "id: real-rule\ntitle: real\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rs, errs := Load(dir)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(rs) != 1 || rs[0].ID != "real-rule" {
		t.Fatalf("loaded %v, want only real-rule", rs)
	}
}
