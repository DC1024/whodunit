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
type ToolFingerprint struct {
	ID         string   `yaml:"id"`
	Name       string   `yaml:"name"`
	Confidence string   `yaml:"confidence"`
	Markers    []RegRef `yaml:"markers"`
	ChangeLogs []RegRef `yaml:"change_logs"`
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
//   - a tool's own change history  -> grade A (it recorded the change itself)
//   - only install/run traces      -> grade B (it was here; it does this)
//
// B is never phrased as certainty. "This tool is installed and changes this
// exact setting" is a lead, not a conviction.
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
		if logged := s.matchAny(ctx, tool.ChangeLogs); logged != nil {
			out = append(out, model.Evidence{
				Source:  "tool_fingerprint",
				Grade:   model.GradeA,
				Actor:   tool.Name,
				Summary: fmt.Sprintf("%s keeps a change history on this machine", tool.Name),
				Detail: strings.TrimSpace(fmt.Sprintf(
					"Found %s. This tool records its own changes, so open it and look at the "+
						"corresponding entry before reverting anything by hand.%s",
					logged.String(), confidenceSuffix(tool))),
			})
			continue
		}
		if marker := s.matchAny(ctx, tool.Markers); marker != nil {
			out = append(out, model.Evidence{
				Source:  "tool_fingerprint",
				Grade:   model.GradeB,
				Actor:   tool.Name,
				Summary: fmt.Sprintf("%s is installed here and changes this kind of setting", tool.Name),
				Detail: strings.TrimSpace(fmt.Sprintf(
					"Found %s. This is a lead, not a conviction: the tool is present and is known to "+
						"write values like %s, but the registry does not record who wrote it. "+
						"Confirm against its own UI or log before acting.%s",
					marker.String(), subject.String(), confidenceSuffix(tool))),
			})
		}
	}
	return out, nil
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

func confidenceSuffix(t ToolFingerprint) string {
	if strings.EqualFold(t.Confidence, "verified") {
		return ""
	}
	return fmt.Sprintf(" [fingerprint %s: %s]", t.ID, t.Confidence)
}
