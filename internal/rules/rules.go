// Package rules loads attribution rules from YAML.
//
// A rule is data, not code. Contributing a new check should mean writing one
// YAML file, not reading the engine. The engine only understands the shape
// declared here; anything platform-specific lives in internal/sources.
package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DC1024/whodunit/internal/model"
)

// Check is one predicate that decides whether the rule applies.
//
// Which fields matter depends on the detect kind:
//
//	registry : path + name
//	service  : field (service name) + property (state | start_type)
//	powercfg : field (sleep state, e.g. hibernate) - equals available/unavailable
//	printer  : field (default | offline | count) + property (optional filter)
type Check struct {
	Path     string `yaml:"path"`     // HKLM\SOFTWARE\Policies\...\AU
	Name     string `yaml:"name"`     // NoAutoUpdate
	Field    string `yaml:"field"`    // wuauserv, hibernate, default
	Property string `yaml:"property"` // state, start_type
	Equals   string `yaml:"equals"`   // "1", DISABLED, unavailable
	Exists   *bool  `yaml:"exists"`   // present / absent
	Required bool   `yaml:"required"` // when true, a miss fails the whole rule
	Note     string `yaml:"note"`     // shown when this check trips
}

// Detect describes how to tell the symptom is present.
type Detect struct {
	Kind   string  `yaml:"kind"`
	Checks []Check `yaml:"checks"`
}

// Blames names the subject and the evidence sources to consult, strongest
// first. The engine stops escalating as soon as a source yields grade A.
type Blames struct {
	Subject model.Subject `yaml:"subject"`
	Sources []string      `yaml:"sources"`
}

// Rule is one attribution play.
type Rule struct {
	ID       string          `yaml:"id"`
	Title    string          `yaml:"title"`
	TitleEn  string          `yaml:"title_en,omitempty"`
	Symptom  []string        `yaml:"symptom"`  // free-text keywords users type after `why`
	Severity string          `yaml:"severity"` // info | warn | high
	Detect   Detect          `yaml:"detect"`
	Blame    Blames          `yaml:"blame"`
	Fix      []model.FixStep `yaml:"fix"`
	Notes    string          `yaml:"notes"`
	NotesEn  string          `yaml:"notes_en,omitempty"`

	path string
}

// Path returns the file the rule came from, for error messages.
func (r *Rule) Path() string { return r.path }

// LocalTitle returns the title in the requested language. English is used only
// when asked for and the rule ships an English title; otherwise the original
// title is returned so the listing never goes blank.
func (r *Rule) LocalTitle(lang string) string {
	if lang == "en" && r.TitleEn != "" {
		return r.TitleEn
	}
	return r.Title
}

// LocalNotes returns the explanation in the requested language, with the same
// English-when-available fallback as LocalTitle.
func (r *Rule) LocalNotes(lang string) string {
	if lang == "en" && r.NotesEn != "" {
		return r.NotesEn
	}
	return r.Notes
}

// Matches reports whether any symptom keyword appears in the query.
func (r *Rule) Matches(query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return false
	}
	for _, s := range r.Symptom {
		if strings.Contains(q, strings.ToLower(s)) {
			return true
		}
	}
	// The rule id and title are always fair game: `why wufb-security-only`.
	if strings.Contains(q, strings.ToLower(r.ID)) {
		return true
	}
	return false
}

// Load reads every .yaml file in dir, skipping files that start with "_".
// One malformed file is reported but does not abort the rest: a broken rule
// should not take down a diagnosis the user is trying to run right now.
func Load(dir string) ([]*Rule, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{fmt.Errorf("read rules dir: %w", err)}
	}
	var (
		rules []*Rule
		errs  []error
	)
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		full := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(full)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
			continue
		}
		r, errs2 := parseOne(raw, full)
		errs = append(errs, errs2...)
		if r != nil {
			rules = append(rules, r)
		}
	}
	return rules, errs
}

// parseOne decodes a single rule. name is only used for error messages, so it
// can be a real path or an embedded filename.
func parseOne(raw []byte, name string) (*Rule, []error) {
	var r Rule
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, []error{fmt.Errorf("%s: %w", name, err)}
	}
	if r.ID == "" {
		return nil, []error{fmt.Errorf("%s: missing id", name)}
	}
	r.path = name
	return &r, nil
}
