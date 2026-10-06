// Package report renders findings for humans and for machines.
//
// The markdown output is designed to be pasted into a forum thread or an issue
// as-is. That is deliberate: every pasted report is a piece of evidence that
// somebody else can reason about without re-running the tool.
//
// Every piece of prose here is language-aware. The chrome (headings, field
// labels, the "nothing matched" note) switches with -lang, matching the rule
// text the engine already localizes, so a report reads in one language top to
// bottom instead of flipping to English halfway down.
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

// Markdown renders findings as a paste-ready report in the given language
// ("en" / "zh"; anything else falls back to Chinese).
func Markdown(h Header, findings []*model.Finding, lang string) string {
	var b strings.Builder
	b.WriteString("# whodunit report\n\n")
	b.WriteString(fmt.Sprintf("- %s: %s\n", model.Pick(lang, "generated", "生成时间"),
		h.Generated.Format("2006-01-02 15:04:05 -0700")))
	if h.Hostname != "" {
		b.WriteString(fmt.Sprintf("- %s: %s\n", model.Pick(lang, "machine", "机器"), h.Hostname))
	}
	b.WriteString(fmt.Sprintf("- %s: %s\n", model.Pick(lang, "os", "系统"), h.OS))
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
		b.WriteString(model.Pick(lang,
			"No known cause matched. That is not the same as \"nothing is wrong\":\n"+
				"it means none of the shipped rules recognised this machine's state.\n",
			"未匹配到已知原因。这并不等于「一切正常」：\n"+
				"只是说内置规则里没有一条能识别本机当前的状态。\n"))
	}

	for _, f := range ordered {
		b.WriteString("\n---\n\n")
		b.WriteString(markdownOne(f, lang))
	}
	return b.String()
}

func markdownOne(f *model.Finding, lang string) string {
	var b strings.Builder
	var status string
	switch {
	case f.Unsupported != "":
		status = model.Pick(lang, "skipped", "跳过")
	case f.Detected:
		status = model.Pick(lang, "DETECTED", "命中")
	default:
		status = model.Pick(lang, "not detected", "未命中")
	}
	b.WriteString(fmt.Sprintf("## [%s] %s\n\n", status, f.RuleID))
	if f.Title != "" {
		b.WriteString(fmt.Sprintf("**%s**\n\n", f.Title))
	}
	if f.Unsupported != "" {
		b.WriteString(fmt.Sprintf("> %s: %s\n", model.Pick(lang, "skipped", "已跳过"), f.Unsupported))
		return b.String()
	}
	if !f.Detected {
		b.WriteString(model.Pick(lang,
			"This rule did not match. Nothing to attribute.\n",
			"此规则未命中，无需归因。\n"))
		return b.String()
	}
	if f.Current != "" {
		b.WriteString(fmt.Sprintf("- %s: `%s`\n", model.Pick(lang, "observed", "观测值"), f.Current))
	}
	if f.Subject.String() != "" {
		b.WriteString(fmt.Sprintf("- %s: `%s`\n", model.Pick(lang, "subject", "对象"), f.Subject.String()))
	}
	if f.Conclusion != "" {
		b.WriteString(fmt.Sprintf("- %s: %s\n", model.Pick(lang, "what it means", "含义"),
			strings.TrimSpace(f.Conclusion)))
	}
	if f.Culprit != nil {
		b.WriteString(fmt.Sprintf("- **%s: %s**\n", model.Pick(lang, "attributed to", "归因"),
			f.Culprit.CulpritLine(lang)))
	} else {
		b.WriteString(fmt.Sprintf("- %s: %s\n", model.Pick(lang, "attributed to", "归因"),
			model.Pick(lang,
				"nothing. No source could produce evidence.",
				"无。没有任何证据源能给出证据。")))
	}
	b.WriteString("\n")
	b.WriteString(evidenceTable(f.Chain, lang))
	if len(f.Fix) > 0 {
		b.WriteString("\n")
		b.WriteString(model.Pick(lang,
			"Revert (printed only; whodunit does not run these):\n\n",
			"回滚（仅打印；whodunit 不会执行）：\n\n"))
		for i, step := range f.Fix {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step.Desc))
			if step.Command != "" {
				b.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", step.Command))
			}
		}
	}
	return b.String()
}

func evidenceTable(chain []model.Evidence, lang string) string {
	if len(chain) == 0 {
		return model.Pick(lang, "_no evidence collected_\n", "_未收集到证据_\n")
	}
	ordered := make([]model.Evidence, len(chain))
	copy(ordered, chain)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Grade.Better(ordered[j].Grade)
	})
	var b strings.Builder
	b.WriteString(model.Pick(lang,
		"| grade | source | what it proves |\n|---|---|---|\n",
		"| 等级 | 来源 | 能证明什么 |\n|---|---|---|\n"))
	for _, e := range ordered {
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", e.Grade, e.Source, oneLine(e.Summary)))
	}
	b.WriteString("\n")
	b.WriteString(model.Pick(lang, "Details:\n\n", "详情：\n\n"))
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
