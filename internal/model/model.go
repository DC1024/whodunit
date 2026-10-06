// Package model holds the vocabulary whodunit speaks: evidence, grades, findings.
//
// The single most important rule of this package: a grade is a promise about
// how much the evidence actually proves. Downgrading honestly is always
// preferred over inventing an actor we cannot name.
package model

import (
	"fmt"
	"time"
)

// Grade describes how much an evidence actually proves about the culprit.
type Grade string

const (
	// GradeA - direct evidence. A tool's own log or change history names the
	// actor and the moment. This is as good as it gets.
	GradeA Grade = "A"
	// GradeB - strong circumstantial evidence. We know the process or the tool
	// family, e.g. an audit event or a matching fingerprint.
	GradeB Grade = "B"
	// GradeC - time only. We know when the value changed, not who changed it.
	GradeC Grade = "C"
	// GradeD - state only. Even the timestamp is unavailable.
	GradeD Grade = "D"
)

// Rank lets grades be compared. Lower is stronger.
func (g Grade) Rank() int {
	switch g {
	case GradeA:
		return 0
	case GradeB:
		return 1
	case GradeC:
		return 2
	case GradeD:
		return 3
	default:
		return 9
	}
}

// Better reports whether g is stronger than other.
func (g Grade) Better(other Grade) bool { return g.Rank() < other.Rank() }

// String keeps unknown grades honest instead of printing an empty line.
func (g Grade) String() string {
	if g == "" {
		return "unknown"
	}
	return string(g)
}

// Subject is the thing we are trying to explain.
//
// Kind is how the check reaches it: registry_key, service, power_setting or
// printer. RegistryPath is the escape hatch that keeps non-registry subjects
// attributable: a service is configured under
// HKLM\SYSTEM\CurrentControlSet\Services\<name>, so pointing at that key lets
// the timestamp source work even when the subject itself is not a registry
// value. Without it, a service rule could detect but never attribute.
type Subject struct {
	Kind         string `json:"kind" yaml:"kind"`                   // registry_key, service, power_setting, printer
	Path         string `json:"path" yaml:"path"`                   // HKLM\SOFTWARE\Policies\...
	Value        string `json:"value" yaml:"value"`                 // NoAutoUpdate
	RegistryPath string `json:"registry_path,omitempty" yaml:"registry_path,omitempty"`
}

// String renders a subject the way an engineer would paste it into a terminal.
func (s Subject) String() string {
	if s.Kind == "registry_key" {
		if s.Value != "" {
			return fmt.Sprintf("%s\\%s", s.Path, s.Value)
		}
		return s.Path
	}
	if s.Path != "" {
		return fmt.Sprintf("%s:%s", s.Kind, s.Path)
	}
	if s.Value != "" {
		return fmt.Sprintf("%s:%s", s.Kind, s.Value)
	}
	return s.Kind
}

// Evidence is one independent observation about the subject.
type Evidence struct {
	Source  string    `json:"source"`
	Grade   Grade     `json:"grade"`
	Actor   string    `json:"actor,omitempty"`
	At      time.Time `json:"at,omitempty"`
	Summary string    `json:"summary"`
	Detail  string    `json:"detail,omitempty"`
}

// CulpritLine renders the evidence as a single sentence. It never guesses: if
// there is no actor, it says so.
func (e Evidence) CulpritLine() string {
	if e.Actor != "" {
		if !e.At.IsZero() {
			return fmt.Sprintf("%s, %s (evidence %s, %s)", e.Actor, e.At.Format("2006-01-02 15:04:05"), e.Grade, e.Source)
		}
		return fmt.Sprintf("%s (evidence %s, %s)", e.Actor, e.Grade, e.Source)
	}
	if !e.At.IsZero() {
		return fmt.Sprintf("unknown actor, changed at %s (evidence %s, %s)",
			e.At.Format("2006-01-02 15:04:05"), e.Grade, e.Source)
	}
	return fmt.Sprintf("unknown actor, unknown time (evidence %s, %s)", e.Grade, e.Source)
}

// FixStep is a revert action. whodunit prints these; it does not run them
// unless the user passes --fix, and even then it prints first.
type FixStep struct {
	Desc    string `json:"desc"`
	Command string `json:"command"`
}

// Finding is what whodunit says about one rule.
type Finding struct {
	RuleID      string     `json:"rule_id"`
	Title       string     `json:"title"`
	Detected    bool       `json:"detected"`
	Conclusion  string     `json:"conclusion,omitempty"`
	Subject     Subject    `json:"subject"`
	Current     string     `json:"current,omitempty"`
	Culprit     *Evidence  `json:"culprit,omitempty"`
	Chain       []Evidence `json:"evidence_chain"`
	Fix         []FixStep  `json:"fix,omitempty"`
	Unsupported string     `json:"unsupported,omitempty"`
}

// BestEvidence returns the strongest piece of evidence collected, or nil.
func (f *Finding) BestEvidence() *Evidence {
	var best *Evidence
	for i := range f.Chain {
		e := f.Chain[i]
		if best == nil || e.Grade.Better(best.Grade) {
			best = &f.Chain[i]
		}
	}
	return best
}
