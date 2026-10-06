package report

import (
	"strings"
	"testing"
	"time"

	"github.com/DC1024/whodunit/internal/model"
)

func sampleHeader() Header {
	return Header{
		Version:   "dev",
		Generated: time.Date(2026, 10, 6, 19, 0, 0, 0, time.UTC),
		Hostname:  "DC-PC",
		OS:        "windows/amd64",
	}
}

// sampleFinding is a detected finding with one C-grade evidence item, so the
// chrome around the culprit line and the evidence table is exercised.
func sampleFinding() *model.Finding {
	at := time.Date(2026, 9, 23, 11, 47, 43, 0, time.UTC)
	f := &model.Finding{
		RuleID:     "default-printer-hijacked",
		Title:      "默认打印机被系统自动改掉",
		Detected:   true,
		Conclusion: "系统行为，不是有人动你机器",
		Subject:    model.Subject{Kind: "registry_key", Path: `HKCU\Software\X`, Value: "LegacyDefaultPrinterMode"},
		Current:    "LegacyDefaultPrinterMode=0",
		Chain: []model.Evidence{{
			Source:  "registry_lastwrite",
			Grade:   model.GradeC,
			At:      at,
			Summary: "was last written at 2026-09-23 11:47:43",
		}},
		Fix: []model.FixStep{{Desc: "交回控制权", Command: "reg add ..."}},
	}
	f.Culprit = &f.Chain[0]
	return f
}

// The chrome is not decoration: a half-translated report is what makes users
// distrust the tool. Every label must follow -lang, top to bottom.
func TestMarkdownChineseChrome(t *testing.T) {
	out := Markdown(sampleHeader(), []*model.Finding{sampleFinding()}, "zh")
	for _, want := range []string{"生成时间", "机器", "命中", "观测值", "对象", "含义", "归因", "未知来源",
		"| 等级 | 来源 | 能证明什么 |", "详情", "回滚（仅打印"} {
		if !strings.Contains(out, want) {
			t.Errorf("zh report missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "attributed to") || strings.Contains(out, "what it proves") {
		t.Errorf("zh report leaked English chrome:\n%s", out)
	}
}

func TestMarkdownEnglishChrome(t *testing.T) {
	out := Markdown(sampleHeader(), []*model.Finding{sampleFinding()}, "en")
	for _, want := range []string{"generated", "machine", "DETECTED", "observed", "subject", "what it means",
		"attributed to", "unknown actor", "| grade | source | what it proves |", "Details", "Revert (printed only"} {
		if !strings.Contains(out, want) {
			t.Errorf("en report missing %q\n---\n%s", want, out)
		}
	}
}

func TestMarkdownNoMatchNoteIsLocalized(t *testing.T) {
	clean := &model.Finding{RuleID: "x", Detected: false}

	zh := Markdown(sampleHeader(), []*model.Finding{clean}, "zh")
	if !strings.Contains(zh, "未匹配到已知原因") || !strings.Contains(zh, "此规则未命中") {
		t.Errorf("zh clean report not localized:\n%s", zh)
	}

	en := Markdown(sampleHeader(), []*model.Finding{clean}, "en")
	if !strings.Contains(en, "No known cause matched") || !strings.Contains(en, "This rule did not match") {
		t.Errorf("en clean report not localized:\n%s", en)
	}
}

func TestMarkdownSkippedIsLocalized(t *testing.T) {
	sk := &model.Finding{RuleID: "x", Unsupported: "needs Windows"}

	zh := Markdown(sampleHeader(), []*model.Finding{sk}, "zh")
	if !strings.Contains(zh, "跳过") {
		t.Errorf("zh skipped report not localized:\n%s", zh)
	}

	en := Markdown(sampleHeader(), []*model.Finding{sk}, "en")
	if !strings.Contains(en, "skipped") {
		t.Errorf("en skipped report not localized:\n%s", en)
	}
}

// The culprit sentence is the heart of the report: it must keep admitting
// ignorance in both languages rather than falling back to an English phrase.
func TestCulpritLineIsLocalized(t *testing.T) {
	ev := model.Evidence{
		Source:  "registry_lastwrite",
		Grade:   model.GradeC,
		At:      time.Date(2026, 9, 23, 11, 47, 43, 0, time.UTC),
		Summary: "whatever",
	}
	if got := ev.CulpritLine("zh"); !strings.Contains(got, "未知来源") {
		t.Errorf("zh culprit line = %q, want 未知来源", got)
	}
	if got := ev.CulpritLine("en"); !strings.Contains(got, "unknown actor") {
		t.Errorf("en culprit line = %q, want unknown actor", got)
	}
}
