package sources

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DC1024/whodunit/internal/model"
	"github.com/DC1024/whodunit/internal/probe"
)

// bundled is compiled in so a standalone .exe needs no data files beside it.
//
//go:embed fingerprints/tools.yaml
var bundled []byte

// RegRef points at one registry key.
type RegRef struct {
	Hive string `yaml:"hive"`
	Path string `yaml:"path"`
}

// String renders the reference the way it would appear in regedit.
func (r RegRef) String() string {
	if r.Hive == "" {
		return r.Path
	}
	return r.Hive + `\` + r.Path
}

// ToolFingerprint describes the traces a known tool leaves behind.
//
// ChangeLogs are file paths the tool writes its own receipt to. They are what
// makes grade A honest: the tool itself named the setting it changed, so
// finding that setting in its log is the closest thing to a confession. Markers
// are weaker registry traces that only prove the tool was installed here.
type ToolFingerprint struct {
	ID         string   `yaml:"id"`
	Name       string   `yaml:"name"`
	Confidence string   `yaml:"confidence"`
	Markers    []RegRef `yaml:"markers"`
	ChangeLogs []string `yaml:"change_logs"`
	Note       string   `yaml:"note"`
}

// FingerprintDB is the whole fingerprint library.
type FingerprintDB struct {
	Tools []ToolFingerprint `yaml:"tools"`
}

// LoadFingerprints parses a fingerprint library from raw YAML.
func LoadFingerprints(raw []byte) (*FingerprintDB, error) {
	var db FingerprintDB
	if err := yaml.Unmarshal(raw, &db); err != nil {
		return nil, fmt.Errorf("parse fingerprints: %w", err)
	}
	return &db, nil
}

// DefaultFingerprints returns the compiled-in library.
func DefaultFingerprints() (*FingerprintDB, error) { return LoadFingerprints(bundled) }

// toolFingerprint looks for known tools that were installed or run here.
//
// Grading is deliberately conservative:
//   - the tool's own change log names this exact setting -> grade A (confession)
//   - only install/run traces                            -> grade B (it was here)
//
// B is never phrased as certainty. "This tool is installed and changes this
// exact setting" is a lead, not a conviction. A is only claimed when the tool's
// own receipt mentions the subject; anything less stays B.
type toolFingerprint struct {
	db *FingerprintDB
}

// NewToolFingerprint builds the source from the bundled library. A parse
// failure would be a build-time bug, so it is returned as an error rather
// than panicking mid-investigation.
func NewToolFingerprint() Source {
	db, err := DefaultFingerprints()
	if err != nil {
		return &toolFingerprint{}
	}
	return &toolFingerprint{db: db}
}

func (toolFingerprint) Name() string { return "tool_fingerprint" }

func (s *toolFingerprint) Investigate(ctx Context, subject model.Subject) ([]model.Evidence, error) {
	if s.db == nil {
		return nil, nil
	}
	var out []model.Evidence
	for _, tool := range s.db.Tools {
		if line, logPath, ok := s.matchChangeLog(ctx, tool.ChangeLogs, subject); ok {
			out = append(out, model.Evidence{
				Source: "tool_fingerprint",
				Grade:  model.GradeA,
				Actor:  tool.Name,
				Summary: model.Pick(ctx.Lang,
					fmt.Sprintf("%s's own change history names this setting", tool.Name),
					fmt.Sprintf("%s 自己的变更历史点名了这项设置", tool.Name)),
				Detail: strings.TrimSpace(model.Pick(ctx.Lang,
					fmt.Sprintf("Found %s. Its change history records this setting, so the tool itself "+
						"confirms it made the change: %q. Open the tool and review that entry before "+
						"reverting anything by hand.%s",
						logPath, line, confidenceSuffix(tool, ctx.Lang)),
					fmt.Sprintf("找到 %s。它的变更历史记录了这一项设置，等于工具自己确认做了这次修改：%q。"+
						"回滚前先打开该工具查看这条记录。%s",
						logPath, line, confidenceSuffix(tool, ctx.Lang)))),
			})
			continue
		}
		if marker := s.matchAny(ctx, tool.Markers); marker != nil {
			out = append(out, model.Evidence{
				Source: "tool_fingerprint",
				Grade:  model.GradeB,
				Actor:  tool.Name,
				Summary: model.Pick(ctx.Lang,
					fmt.Sprintf("%s is installed here and changes this kind of setting", tool.Name),
					fmt.Sprintf("%s 已安装在本机，且会修改这类设置", tool.Name)),
				Detail: strings.TrimSpace(model.Pick(ctx.Lang,
					fmt.Sprintf("Found %s. This is a lead, not a conviction: the tool is present and is known to "+
						"write values like %s, but the registry does not record who wrote it. "+
						"Confirm against its own UI or log before acting.%s",
						marker.String(), subject.String(), confidenceSuffix(tool, ctx.Lang)),
					fmt.Sprintf("找到 %s。这是线索而非定罪：该工具存在，且已知会写入类似 %s 的值，"+
						"但注册表不记录是谁写入的。行动前请对照它自己的界面或日志确认。%s",
						marker.String(), subject.String(), confidenceSuffix(tool, ctx.Lang)))),
			})
		}
	}
	return out, nil
}

// matchChangeLog reads each of the tool's log files and returns the first line
// that names the subject, so the report can quote the tool's own words.
func (s *toolFingerprint) matchChangeLog(ctx Context, logs []string, subject model.Subject) (line, path string, ok bool) {
	if ctx.Files == nil || !ctx.Files.Available() {
		return "", "", false
	}
	needles := subjectNeedles(subject)
	if len(needles) == 0 {
		return "", "", false
	}
	for _, p := range logs {
		content, exists, err := ctx.Files.Read(p)
		if err != nil || !exists {
			continue
		}
		if l, found := firstMentioningLine(content, needles); found {
			return l, probe.ResolveLogPath(p), true
		}
	}
	return "", "", false
}

// firstMentioningLine scans a change log for a line that references the
// subject. It returns the trimmed line so it can be quoted verbatim in the
// report rather than summarized into something less checkable.
func firstMentioningLine(content string, needles []string) (string, bool) {
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		lower := strings.ToLower(strings.ReplaceAll(line, "/", `\`))
		matched := true
		for _, n := range needles {
			if !strings.Contains(lower, n) {
				matched = false
				break
			}
		}
		if matched {
			if len(line) > 200 {
				line = line[:200] + "..."
			}
			return line, true
		}
	}
	return "", false
}

// subjectNeedles lists the strings a tool's own log would contain for this
// subject. The registry path is the anchor; a value name is only added as a
// second required needle when it is specific enough to cut false positives.
//
// For a non-registry subject (service, power setting, printer) Path holds the
// short identifier — "wuauserv", "hibernate" — and RegistryPath holds where it
// is actually configured. A tool's log writes the registry path, so that is the
// one to match on, exactly as registry_lastwrite already does.
func subjectNeedles(subject model.Subject) []string {
	base := subject.Path
	if subject.Kind != "registry_key" {
		base = subject.RegistryPath
	}
	if base == "" {
		return nil
	}
	norm := strings.ToLower(strings.ReplaceAll(base, "/", `\`))
	needles := []string{norm}
	if subject.Value != "" && len([]rune(subject.Value)) >= 6 {
		needles = append(needles, strings.ToLower(subject.Value))
	}
	return needles
}

func (s *toolFingerprint) matchAny(ctx Context, refs []RegRef) *RegRef {
	for i := range refs {
		ref := refs[i]
		ok, err := ctx.Registry.KeyExists(ref.Hive, ref.Path)
		if err != nil {
			if errors.Is(err, probe.ErrUnsupported) {
				return nil
			}
			continue
		}
		if ok {
			return &ref
		}
	}
	return nil
}

func confidenceSuffix(t ToolFingerprint, lang string) string {
	if strings.EqualFold(t.Confidence, "verified") {
		return ""
	}
	return model.Pick(lang,
		fmt.Sprintf(" [fingerprint %s: %s]", t.ID, t.Confidence),
		fmt.Sprintf(" [指纹 %s：%s]", t.ID, t.Confidence))
}
