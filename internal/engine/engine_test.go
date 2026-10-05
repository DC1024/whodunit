package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/DC1024/whodunit/internal/model"
	"github.com/DC1024/whodunit/internal/rules"
	"github.com/DC1024/whodunit/internal/sources"
)

// fakeRegistry is an in-memory stand-in for the Windows registry. Keys are
// "HIVE\path|name" for values and "HIVE\path" for keys, which keeps fixtures
// readable in the tests below.
type fakeRegistry struct {
	values map[string]string
	keys   map[string]bool
	times  map[string]time.Time
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		values: map[string]string{},
		keys:   map[string]bool{},
		times:  map[string]time.Time{},
	}
}

func (f *fakeRegistry) Set(hive, path, name, value string) *fakeRegistry {
	f.values[hive+`\`+path+`|`+name] = value
	return f
}

func (f *fakeRegistry) SetKey(hive, path string) *fakeRegistry {
	f.keys[hive+`\`+path] = true
	return f
}

func (f *fakeRegistry) SetTime(hive, path string, at time.Time) *fakeRegistry {
	f.times[hive+`\`+path] = at
	return f
}

func (f *fakeRegistry) GetString(hive, path, name string) (string, bool, error) {
	v, ok := f.values[hive+`\`+path+`|`+name]
	return v, ok, nil
}

func (f *fakeRegistry) KeyLastWrite(hive, path string) (time.Time, error) {
	return f.times[hive+`\`+path], nil
}

func (f *fakeRegistry) KeyExists(hive, path string) (bool, error) {
	if f.keys[hive+`\`+path] {
		return true, nil
	}
	prefix := hive + `\` + path + `|`
	for k := range f.values {
		if strings.HasPrefix(k, prefix) {
			return true, nil
		}
	}
	return false, nil
}

func rule(t *testing.T, id string) *rules.Rule {
	t.Helper()
	all, errs := rules.LoadEmbedded()
	if len(errs) > 0 {
		t.Fatalf("load embedded rules: %v", errs)
	}
	for _, r := range all {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %q not found in builtin set", id)
	return nil
}

func newEngine(reg *fakeRegistry) *Engine {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	return New(reg, sources.New(), now)
}

// A tool's own change history is grade A: it is the tool admitting it.
func TestAttributeGradeAWhenToolChangeHistoryPresent(t *testing.T) {
	reg := newFakeRegistry().
		Set("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "DisableWindowsUpdateAccess", "1").
		SetKey("HKCU", `Software\Winhance\ChangeHistory`)

	f, err := newEngine(reg).Evaluate(rule(t, "wufb-feature-update-blocked"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !f.Detected {
		t.Fatalf("expected the rule to detect the policy, got clean")
	}
	if f.Culprit == nil {
		t.Fatalf("expected a culprit, got none")
	}
	if f.Culprit.Grade != model.GradeA {
		t.Errorf("grade = %s, want A", f.Culprit.Grade)
	}
	if f.Culprit.Actor != "Winhance" {
		t.Errorf("actor = %q, want Winhance", f.Culprit.Actor)
	}
	if f.Current == "" {
		t.Error("expected the observed value to be reported")
	}
}

// Only an install trace is grade B, and it must be phrased as a lead. That
// phrasing lives in the source; what the test can assert is the grade.
func TestGradeBWhenOnlyInstallTracePresent(t *testing.T) {
	reg := newFakeRegistry().
		Set("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "DisableWindowsUpdateAccess", "1").
		SetKey("HKCU", `Software\Winhance`)

	f, err := newEngine(reg).Evaluate(rule(t, "wufb-feature-update-blocked"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if f.Culprit == nil || f.Culprit.Grade != model.GradeB {
		t.Fatalf("grade = %v, want B", f.Culprit)
	}
	for _, e := range f.Chain {
		if e.Grade == model.GradeB && e.Actor == "" {
			t.Error("grade B evidence must still name a suspect")
		}
	}
}

// No tool, no log: the only thing left is the key's own FILETIME, and the
// finding must say the actor is unknown rather than invent one.
func TestGradeCWhenOnlyTimestampAvailable(t *testing.T) {
	changed := time.Date(2026, 9, 3, 7, 41, 22, 0, time.UTC)
	reg := newFakeRegistry().
		Set("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "DisableWindowsUpdateAccess", "1").
		SetTime("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, changed)

	f, err := newEngine(reg).Evaluate(rule(t, "wufb-feature-update-blocked"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if f.Culprit == nil {
		t.Fatalf("expected timestamp evidence, got none")
	}
	if f.Culprit.Grade != model.GradeC {
		t.Errorf("grade = %s, want C", f.Culprit.Grade)
	}
	if f.Culprit.Actor != "" {
		t.Errorf("actor must stay empty when nothing proves it, got %q", f.Culprit.Actor)
	}
	if !f.Culprit.At.Equal(changed) {
		t.Errorf("time = %s, want %s", f.Culprit.At, changed)
	}
	if !strings.Contains(f.Culprit.CulpritLine(), "unknown actor") {
		t.Errorf("culprit line must admit ignorance, got %q", f.Culprit.CulpritLine())
	}
}

func TestCleanMachineIsNotDetected(t *testing.T) {
	reg := newFakeRegistry()
	f, err := newEngine(reg).Evaluate(rule(t, "wufb-feature-update-blocked"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if f.Detected {
		t.Error("a machine with none of the policy values must not be flagged")
	}
	if f.Culprit != nil {
		t.Error("no detection means no attribution")
	}
}

// An optional check that is absent, with the rest of the rule satisfied, must
// not count as a hit: OR semantics only ever widen, never invent.
func TestSleepRuleRequiresAtLeastOneOptionalCheck(t *testing.T) {
	reg := newFakeRegistry().
		Set("HKLM", `SYSTEM\CurrentControlSet\Control\Power`, "HibernateEnabled", "1")
	f, err := newEngine(reg).Evaluate(rule(t, "sleep-hibernate-disabled"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if f.Detected {
		t.Error("HibernateEnabled=1 means hibernate is on; the rule must stay clean")
	}
}

func TestSleepRuleDetectsDisabledHibernate(t *testing.T) {
	reg := newFakeRegistry().
		Set("HKLM", `SYSTEM\CurrentControlSet\Control\Power`, "HibernateEnabled", "0")
	f, err := newEngine(reg).Evaluate(rule(t, "sleep-hibernate-disabled"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !f.Detected {
		t.Fatal("HibernateEnabled=0 must be detected")
	}
	if !strings.Contains(f.Current, "HibernateEnabled=0") {
		t.Errorf("current = %q, want it to name the value", f.Current)
	}
}

// The printer rule has two optional checks, one of which is "value absent".
// Absence is itself a finding here, which is unusual and worth pinning down.
func TestPrinterRuleTreatsMissingValueAsManagedByWindows(t *testing.T) {
	reg := newFakeRegistry()
	f, err := newEngine(reg).Evaluate(rule(t, "default-printer-hijacked"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !f.Detected {
		t.Fatal("a missing LegacyDefaultPrinterMode means Windows owns the default printer")
	}
}

func TestPrinterRuleCleanWhenUserControlsDefault(t *testing.T) {
	reg := newFakeRegistry().
		Set("HKCU", `Software\Microsoft\Windows NT\CurrentVersion\Windows`, "LegacyDefaultPrinterMode", "1")
	f, err := newEngine(reg).Evaluate(rule(t, "default-printer-hijacked"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if f.Detected {
		t.Error("LegacyDefaultPrinterMode=1 means the user is in control")
	}
}

// Detect kinds other than registry are not implemented yet. The finding must
// say so instead of silently reporting "clean", which would be a lie.
func TestUnimplementedDetectKindIsReported(t *testing.T) {
	r := &rules.Rule{
		ID:     "test-power-kind",
		Title:  "powercfg based rule",
		Detect: rules.Detect{Kind: "powercfg"},
	}
	f, err := newEngine(newFakeRegistry()).Evaluate(r)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if f.Unsupported == "" {
		t.Error("an unimplemented detect kind must be reported as skipped, not clean")
	}
}

func TestEvidenceIsSortedStrongestFirst(t *testing.T) {
	// Grade B only: an install trace but no change history, so the engine keeps
	// asking the remaining sources and the chain has something to sort.
	reg := newFakeRegistry().
		Set("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "DisableWindowsUpdateAccess", "1").
		SetKey("HKCU", `Software\Winhance`).
		SetTime("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, time.Now().Add(-48*time.Hour))

	f, err := newEngine(reg).Evaluate(rule(t, "wufb-feature-update-blocked"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(f.Chain) < 2 {
		t.Fatalf("expected several evidence items, got %d", len(f.Chain))
	}
	for i := 1; i < len(f.Chain); i++ {
		if f.Chain[i].Grade.Better(f.Chain[i-1].Grade) {
			t.Errorf("chain not sorted: %s comes before %s", f.Chain[i-1].Grade, f.Chain[i].Grade)
		}
	}
}

// Grade A stops the search on purpose: nothing can beat a tool admitting it,
// and continuing only adds weaker noise to the report.
func TestGradeAShortCircuitsFurtherSources(t *testing.T) {
	reg := newFakeRegistry().
		Set("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "DisableWindowsUpdateAccess", "1").
		SetKey("HKCU", `Software\Winhance\ChangeHistory`).
		SetTime("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, time.Now().Add(-48*time.Hour))

	f, err := newEngine(reg).Evaluate(rule(t, "wufb-feature-update-blocked"))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(f.Chain) != 1 {
		t.Errorf("chain length = %d, want 1: grade A should end the search", len(f.Chain))
	}
	if f.Culprit == nil || f.Culprit.Grade != model.GradeA {
		t.Fatalf("culprit = %v, want grade A", f.Culprit)
	}
}
