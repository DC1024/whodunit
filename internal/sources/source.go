// Package sources holds the evidence collectors.
//
// Each source answers the same question from a different angle: who changed
// this, and when. A source never guesses. If it cannot name an actor it
// returns evidence with an empty Actor and a lower grade, and the engine
// reports exactly that.
package sources

import (
	"time"

	"github.com/DC1024/whodunit/internal/model"
	"github.com/DC1024/whodunit/internal/probe"
)

// Context carries everything a source is allowed to touch.
type Context struct {
	Registry probe.Registry
	// Files reads a tool's own log files. It is how the tool_fingerprint source
	// earns grade A: the culprit's receipt, read from disk.
	Files probe.Files
	Now   time.Time
	// Lang is the report language ("en" / "zh"). Sources use it to pick the
	// wording of the evidence they emit so a whole report reads in one language
	// instead of switching to English halfway down.
	Lang string
}

// Source is one evidence collector.
type Source interface {
	// Name is the identifier used in rule YAML and printed in reports.
	Name() string
	// Investigate returns whatever evidence it can find. It returns an empty
	// slice (not an error) when it simply has nothing to say.
	Investigate(ctx Context, subject model.Subject) ([]model.Evidence, error)
}

// Registry holds the built-in sources by name.
type Registry struct {
	all map[string]Source
}

// New returns a registry populated with every built-in source.
func New() *Registry {
	r := &Registry{all: map[string]Source{}}
	for _, s := range []Source{
		NewToolFingerprint(),
		NewRegistryLastWrite(),
		NewPolicyOrigin(),
		NewEventAudit(),
	} {
		r.all[s.Name()] = s
	}
	return r
}

// Get returns a source by the name used in rule YAML, or nil.
func (r *Registry) Get(name string) (Source, bool) {
	s, ok := r.all[name]
	return s, ok
}

// Names lists every known source, for `whodunit rules --sources`.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.all))
	for n := range r.all {
		names = append(names, n)
	}
	return names
}

// nowOrZero keeps zero times out of JSON output when a source has no timestamp.
func nowOrZero(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC()
}
