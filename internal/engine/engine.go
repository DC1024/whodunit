// Package engine turns a rule plus the current machine state into a finding.
//
// The engine never decides guilt. It collects what each source can prove,
// sorts by strength, and reports the strongest. When nothing can name an
// actor, the finding says so.
package engine

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DC1024/whodunit/internal/model"
	"github.com/DC1024/whodunit/internal/probe"
	"github.com/DC1024/whodunit/internal/rules"
	"github.com/DC1024/whodunit/internal/sources"
)

// Engine evaluates rules against one machine.
type Engine struct {
	reg probe.Registry
	src *sources.Registry
	now time.Time
}

// New builds an engine. now is injectable so reports are reproducible in tests.
func New(reg probe.Registry, src *sources.Registry, now time.Time) *Engine {
	if now.IsZero() {
		now = time.Now()
	}
	return &Engine{reg: reg, src: src, now: now}
}

// Evaluate runs one rule end to end: detect, then blame.
func (e *Engine) Evaluate(r *rules.Rule) (*model.Finding, error) {
	f := &model.Finding{
		RuleID:   r.ID,
		Title:    r.Title,
		Subject:  r.Blame.Subject,
		Fix:      r.Fix,
		Detected: false,
	}
	if r.Detect.Kind != "registry" {
		f.Unsupported = fmt.Sprintf("detect kind %q is not implemented yet (only \"registry\")", r.Detect.Kind)
		return f, nil
	}
	detected, current, err := e.detect(r)
	if err != nil {
		if errors.Is(err, probe.ErrUnsupported) {
			f.Unsupported = "this platform has no registry to read (Windows only)"
			return f, nil
		}
		return nil, err
	}
	f.Current = current
	if !detected {
		return f, nil
	}
	f.Detected = true
	f.Conclusion = r.Notes
	e.blame(r, f)
	// The chain is ordered here, not by the renderer: every consumer should see
	// the strongest evidence first, whether that is a human or a JSON diff.
	sort.SliceStable(f.Chain, func(i, j int) bool {
		return f.Chain[i].Grade.Better(f.Chain[j].Grade)
	})
	f.Culprit = f.BestEvidence()
	return f, nil
}

// EvaluateAll runs every rule.
func (e *Engine) EvaluateAll(rs []*rules.Rule) ([]*model.Finding, error) {
	out := make([]*model.Finding, 0, len(rs))
	for _, r := range rs {
		f, err := e.Evaluate(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.ID, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// detect applies the rule's checks.
//
// Semantics, because this is the part contributors get wrong:
//   - every check marked required must hit
//   - if the rule also has optional checks, at least one of those must hit
//   - an all-required rule is hit when all of them hit
func (e *Engine) detect(r *rules.Rule) (bool, string, error) {
	var (
		optionalTotal, optionalHits int
		hits                        []string
	)
	for _, c := range r.Detect.Checks {
		hit, desc, err := e.checkOne(c)
		if err != nil {
			return false, "", err
		}
		if !c.Required {
			optionalTotal++
		}
		if hit {
			if !c.Required {
				optionalHits++
			}
			if desc != "" {
				hits = append(hits, desc)
			}
		} else if c.Required {
			return false, "", nil
		}
	}
	if optionalTotal > 0 && optionalHits == 0 {
		return false, "", nil
	}
	if len(r.Detect.Checks) == 0 {
		return false, "", nil
	}
	return true, strings.Join(hits, "; "), nil
}

// checkOne evaluates a single check, returning whether it hit and how to
// describe the observed value.
func (e *Engine) checkOne(c rules.Check) (bool, string, error) {
	hive, rest := probe.SplitHive(c.Path)
	if c.Name == "" {
		ok, err := e.reg.KeyExists(hive, rest)
		if err != nil {
			return false, "", err
		}
		if c.Exists != nil && *c.Exists != ok {
			return false, "", nil
		}
		if ok {
			return true, describe(c, "present"), nil
		}
		return false, "", nil
	}
	val, ok, err := e.reg.GetString(hive, rest, c.Name)
	if err != nil {
		return false, "", err
	}
	if c.Exists != nil {
		if *c.Exists && !ok {
			return false, "", nil
		}
		if !*c.Exists && ok {
			return false, "", nil
		}
		return true, describe(c, orAbsent(ok, val)), nil
	}
	if !ok {
		return false, "", nil
	}
	if c.Equals != "" && val != c.Equals {
		return false, "", nil
	}
	return true, describe(c, val), nil
}

func describe(c rules.Check, val string) string {
	name := c.Name
	if name == "" {
		name = c.Path
	}
	switch val {
	case "absent", "present":
		return fmt.Sprintf("%s %s", name, val)
	}
	return fmt.Sprintf("%s=%s", name, val)
}

func orAbsent(ok bool, val string) string {
	if !ok {
		return "absent"
	}
	return val
}

// blame asks each source in the rule's order. A grade A hit stops the search:
// stronger evidence cannot be improved on, and extra noise only dilutes it.
func (e *Engine) blame(r *rules.Rule, f *model.Finding) {
	names := r.Blame.Sources
	if len(names) == 0 {
		names = e.src.Names()
	}
	ctx := sources.Context{Registry: e.reg, Now: e.now}
	for _, name := range names {
		src, ok := e.src.Get(name)
		if !ok {
			continue
		}
		evs, err := src.Investigate(ctx, r.Blame.Subject)
		if err != nil {
			// One broken source must not hide the others. Record and move on.
			f.Chain = append(f.Chain, model.Evidence{
				Source:  name,
				Grade:   model.GradeD,
				Summary: "this source failed",
				Detail:  err.Error(),
			})
			continue
		}
		f.Chain = append(f.Chain, evs...)
		for _, ev := range evs {
			if ev.Grade == model.GradeA {
				return
			}
		}
	}
}
