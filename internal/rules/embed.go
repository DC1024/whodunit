package rules

import (
	"embed"
	"path"
	"sort"
	"strings"
)

// builtin holds the shipped rules. They are compiled into the binary so a
// single .exe works with no data files beside it, while still being plain YAML
// in the repository: adding a check means adding a file here.
//
//go:embed builtin/*.yaml
var builtin embed.FS

// LoadEmbedded reads the compiled-in rules.
func LoadEmbedded() ([]*Rule, []error) {
	entries, err := builtin.ReadDir("builtin")
	if err != nil {
		return nil, []error{err}
	}
	var (
		rules []*Rule
		errs  []error
	)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		names = append(names, e.Name())
	}
	// Deterministic order: reports should not shuffle between runs.
	sort.Strings(names)
	for _, name := range names {
		raw, err := builtin.ReadFile(path.Join("builtin", name))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r, errs2 := parseOne(raw, name)
		errs = append(errs, errs2...)
		if r != nil {
			rules = append(rules, r)
		}
	}
	return rules, errs
}
