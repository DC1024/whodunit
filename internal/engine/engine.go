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
	"strconv"
	"strings"
	"time"

	"github.com/DC1024/whodunit/internal/model"
	"github.com/DC1024/whodunit/internal/probe"
	"github.com/DC1024/whodunit/internal/rules"
	"github.com/DC1024/whodunit/internal/sources"
)

// Engine evaluates rules against one machine.
type Engine struct {
	reg  probe.Registry
	cmds probe.Commands
	src  *sources.Registry
	now  time.Time
}

// New builds an engine. Both the registry and the command runner are injected
// so every detect kind can be tested on any platform.
func New(reg probe.Registry, cmds probe.Commands, src *sources.Registry, now time.Time) *Engine {
	if now.IsZero() {
		now = time.Now()
	}
	if cmds == nil {
		cmds = probe.NewCommands()
	}
	return &Engine{reg: reg, cmds: cmds, src: src, now: now}
}

// detectKinds is the set of detect kinds the engine can actually run. Anything
// else is reported as skipped rather than silently treated as "clean": a rule
// that cannot be evaluated must never look like a machine with nothing wrong.
var detectKinds = []string{"registry", "service", "powercfg", "printer"}

func supportedKind(kind string) bool {
	for _, k := range detectKinds {
		if k == kind {
			return true
		}
	}
	return false
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
	if !supportedKind(r.Detect.Kind) {
		f.Unsupported = fmt.Sprintf("detect kind %q is not implemented (supported: %s)",
			r.Detect.Kind, strings.Join(detectKinds, ", "))
		return f, nil
	}
	detected, current, err := e.detect(r)
	if err != nil {
		if errors.Is(err, probe.ErrUnsupported) {
			f.Unsupported = "this needs Windows to inspect; nothing was checked"
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
		hit, desc, err := e.checkOne(r.Detect.Kind, c)
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

// checkOne dispatches to the handler for the rule's detect kind.
func (e *Engine) checkOne(kind string, c rules.Check) (bool, string, error) {
	switch kind {
	case "registry":
		return e.checkRegistry(c)
	case "service":
		return e.checkService(c)
	case "powercfg":
		return e.checkPowercfg(c)
	case "printer":
		return e.checkPrinter(c)
	}
	return false, "", fmt.Errorf("no handler for detect kind %q", kind)
}

// checkService asks sc.exe about one service.
//
// Two properties are meaningful for attribution: state (what it is doing now)
// and start_type (what it will do after a reboot). A disabled Windows Update
// service is the classic "updates are broken" cause, and only start_type tells
// you that it was deliberately disabled rather than merely stopped.
func (e *Engine) checkService(c rules.Check) (bool, string, error) {
	if c.Field == "" {
		return false, "", fmt.Errorf("service check needs a field: the service name")
	}
	if !e.cmds.Available() {
		return false, "", probe.ErrUnsupported
	}
	prop := strings.ToLower(c.Property)
	if prop == "" {
		prop = "state"
	}
	var out string
	var err error
	switch prop {
	case "start_type":
		out, err = e.cmds.Output("sc", probe.ServiceConfig(c.Field)...)
	default:
		out, err = e.cmds.Output("sc", probe.ServiceQuery(c.Field)...)
	}
	// sc.exe exits non-zero when the service does not exist. That is a clean
	// miss, not an investigation failure.
	if err != nil {
		return false, "", nil
	}
	var (
		value string
		found bool
	)
	if prop == "start_type" {
		value, found = probe.ParseServiceStartType(out)
	} else {
		value, found = probe.ParseServiceState(out)
	}
	if !found {
		return false, "", nil
	}
	if !valuesEqual(c.Equals, value) {
		return false, "", nil
	}
	return true, fmt.Sprintf("%s %s=%s", c.Field, prop, value), nil
}

// checkPowercfg asks whether a sleep state is actually available. This is the
// ground truth for hibernate: the registry can say enabled while the firmware
// or a policy still keeps it off the menu.
func (e *Engine) checkPowercfg(c rules.Check) (bool, string, error) {
	if c.Field == "" {
		return false, "", fmt.Errorf("powercfg check needs a field: the sleep state, e.g. hibernate")
	}
	if !e.cmds.Available() {
		return false, "", probe.ErrUnsupported
	}
	out, err := e.cmds.Output("powercfg", probe.SleepStates()...)
	if err != nil {
		return false, "", nil
	}
	available, found := probe.ParseSleepAvailability(out, c.Field)
	if !found {
		// The state is not mentioned at all. Reporting "clean" here would be a
		// guess, so it counts as a miss.
		return false, "", nil
	}
	want := true
	if c.Equals != "" {
		want = strings.EqualFold(c.Equals, "available")
	}
	if want != available {
		return false, "", nil
	}
	state := "unavailable"
	if available {
		state = "available"
	}
	return true, fmt.Sprintf("%s %s", c.Field, state), nil
}

// checkPrinter inspects the printer inventory. field picks what to look at:
// default, offline, or count.
func (e *Engine) checkPrinter(c rules.Check) (bool, string, error) {
	if !e.cmds.Available() {
		return false, "", probe.ErrUnsupported
	}
	name, args := probe.PrinterInventory()
	out, err := e.cmds.Output(name, args...)
	if err != nil {
		return false, "", nil
	}
	printers := probe.ParsePrinters(probe.NormalizePrinterOutput(out))
	switch strings.ToLower(c.Field) {
	case "", "default":
		var def *probe.PrinterInfo
		for i := range printers {
			if printers[i].Default {
				def = &printers[i]
				break
			}
		}
		has := def != nil
		if c.Exists != nil {
			if *c.Exists != has {
				return false, "", nil
			}
			if has {
				return true, "default printer: " + def.Name, nil
			}
			return true, "no default printer", nil
		}
		if !has {
			return false, "", nil
		}
		if c.Equals != "" && !strings.EqualFold(def.Name, c.Equals) {
			return false, "", nil
		}
		return true, "default printer: " + def.Name, nil

	case "offline":
		var names []string
		for _, p := range printers {
			if p.WorkOffline {
				names = append(names, p.Name)
			}
		}
		has := len(names) > 0
		if c.Exists != nil {
			if *c.Exists != has {
				return false, "", nil
			}
			if has {
				return true, fmt.Sprintf("offline: %s", strings.Join(names, ", ")), nil
			}
			return true, "no offline printers", nil
		}
		if !has {
			return false, "", nil
		}
		return true, fmt.Sprintf("offline: %s", strings.Join(names, ", ")), nil

	case "count":
		n := strconv.Itoa(len(printers))
		if c.Equals == "" {
			return false, "", fmt.Errorf("printer count check needs equals")
		}
		if c.Equals != n {
			return false, "", nil
		}
		return true, fmt.Sprintf("printer count=%s", n), nil
	}
	return false, "", fmt.Errorf("unknown printer field %q", c.Field)
}

// valuesEqual compares a rule's expected value with an observed one. Command
// output is compared case-insensitively because sc.exe and powercfg are not
// consistent about casing across Windows versions.
func valuesEqual(want, got string) bool {
	if want == "" {
		return true
	}
	return strings.EqualFold(want, got)
}

// checkRegistry evaluates one registry check, returning whether it hit and how
// to describe the observed value.
func (e *Engine) checkRegistry(c rules.Check) (bool, string, error) {
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
