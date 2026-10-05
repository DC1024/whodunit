// Package report renders findings for humans and for machines.
//
// The markdown output is designed to be pasted into a forum thread or an issue
// as-is. That is deliberate: every pasted report is a piece of evidence that
// somebody else can reason about without re-running the tool.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DC1024/whodunit/internal/model"
)

// Header is the metadata printed at the top of a report.
type Header struct {
	Version   string
	Generated time.Time
	Hostname  string
	OS        string
}

// Markdown renders findings as a paste-ready report.
func Markdown(h Header, findings []*model.Finding) string {
	var b strings.Builder
	b.WriteString("# whodunit report\n\n")
	b.WriteString(fmt.Sprintf("- generated: %s\n", h.Generated.Format("2006-01-02 15:04:05 -0700")))
	if h.Hostname != "" {
		b.WriteString(fmt.Sprintf("- machine: %s\n", h.Hostname))
	}
	b.WriteString(fmt.Sprintf("- os: %s\n", h.OS))
	b.WriteString(fmt.Sprintf("- whodunit: %s\n\n", h.Version))

	// Strongest findings first: the thing that actually explains the symptom
	// should not sit below a noise hit.
	ordered := make([]*model.Finding, len(findings))
	copy(ordered, findings)
	sort.SliceStable(ordered, func(i, j int) bool {
		return severityRank(ordered[i]) > severityRank(ordered[j])
	})

	hit := 0
	for _, f := range ordered {
		if f.Detected {
			hit++
		}
	}
	if hit == 0 {
		b.WriteString("No known cause matched. That is not the same as \"nothing is wrong\":\n")
		b.WriteString("it means none of the shipped rules recognised this machine's state.\n")
	}

	for _, f := range ordered {
		b.WriteString("\n---\n\n")
		b.WriteString(markdownOne(f))
	}
	return b.String()
}

func markdownOne(f *model.Finding) string {
	var b strings.Builder
	status := "not detected"
	if f.Detected {
		status = "DETECTED"
	}
	if f.Unsupported != "" {
		status = "skipped"
	}
	b.WriteString(fmt.Sprintf("## [%s] %s\n\n", status, f.RuleID))
	if f.Title != "" {
		b.WriteString(fmt.Sprintf("**%s**\n\n", f.Title))
	}
	if f.Unsupported != "" {
		b.WriteString(fmt.Sprintf("> skipped: %s\n", f.Unsupported))
		return b.String()
	}
	if !f.Detected {
		b.WriteString("This rule did not match. Nothing to attribute.\n")
		return b.String()
	}
	if f.Current != "" {
		b.WriteString(fmt.Sprintf("- observed: `%s`\n", f.Current))
	}
	if f.Subject.String() != "" {
		b.WriteString(fmt.Sprintf("- subject: `%s`\n", f.Subject.String()))
	}
	if f.Conclusion != "" {
		b.WriteString(fmt.Sprintf("- what it means: %s\n", strings.TrimSpace(f.Conclusion)))
	}
	if f.Culprit != nil {
		b.WriteString(fmt.Sprintf("- **attributed to: %s**\n", f.Culprit.CulpritLine()))
	} else {
		b.WriteString("- attributed to: nothing. No source could produce evidence.\n")
	}
	b.WriteString("\n")
	b.WriteString(evidenceTable(f.Chain))
	if len(f.Fix) > 0 {
		b.WriteString("\nRevert (printed only; whodunit does not run these):\n\n")
		for i, step := range f.Fix {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step.Desc))
			if step.Command != "" {
				b.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", step.Command))
			}
		}
	}
	return b.String()
}

func evidenceTable(chain []model.Evidence) string {
	if len(chain) == 0 {
		return "_no evidence collected_\n"
	}
	ordered := make([]model.Evidence, len(chain))
	copy(ordered, chain)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Grade.Better(ordered[j].Grade)
	})
	var b strings.Builder
	b.WriteString("| grade | source | what it proves |\n")
	b.WriteString("|---|---|---|\n")
	for _, e := range ordered {
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", e.Grade, e.Source, oneLine(e.Summary)))
	}
	b.WriteString("\nDetails:\n\n")
	for _, e := range ordered {
		b.WriteString(fmt.Sprintf("- **%s / %s** — %s\n", e.Grade, e.Source, oneLine(e.Summary)))
		if e.Detail != "" {
			b.WriteString(fmt.Sprintf("  %s\n", oneLine(e.Detail)))
		}
	}
	return b.String()
}

// JSON renders findings as an array. Evidence grades stay strings so the
// output is diffable in git.
func JSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func oneLine(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
}

func severityRank(f *model.Finding) int {
	// Detected beats skipped beats clean; severity is only a tiebreaker and
	// lives in the rule, which the finding does not carry, so we approximate
	// with detection state alone. Keeps ordering stable and obvious.
	switch {
	case !f.Detected && f.Unsupported != "":
		return 0
	case !f.Detected:
		return 1
	default:
		return 2
	}
}
