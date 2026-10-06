package probe

import (
	"os"
	"path/filepath"
	"strings"
)

// Files reads a tool's own change-log files.
//
// This is the one probe that is not Windows-specific: reading a file is the
// same everywhere, and on a non-Windows host the tool's log simply is not
// there (a clean miss, not an error). It exists because grade A is only honest
// when it comes from the culprit's own receipt — a debloat tool that writes
// "I changed X" to a log file is naming itself, which no amount of registry
// snooping can.
type Files interface {
	// Read returns the file's text and whether it exists. A missing file is
	// (",", false, nil): the tool may not be installed, which is a clean miss.
	Read(path string) (string, bool, error)
	// Available reports whether file reads can happen at all.
	Available() bool
}

// NewFiles returns the file reader for the running platform.
func NewFiles() Files { return fileReader{} }

type fileReader struct{}

func (fileReader) Available() bool { return true }

func (fileReader) Read(path string) (string, bool, error) {
	resolved := ResolveLogPath(path)
	data, err := os.ReadFile(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		// A permission error on another user's ProgramData is also a miss:
		// we cannot prove the tool wrote anything, so we must not claim it.
		return "", false, nil
	}
	return string(data), true, nil
}

// changelogRootEnv redirects change-log lookups to a directory of fixtures.
//
// Two uses, both legitimate: a rule author testing a new fingerprint without
// installing the tool, and whodunit's own demo, which needs a reproducible
// A-grade attribution on a machine that has no debloat tool installed. When it
// is set, every change-log path resolves to <root>/<basename>.
const changelogRootEnv = "WHODUNIT_CHANGELOG_ROOT"

// ResolveLogPath expands %VAR% (and $VAR / ${VAR}) and applies the fixture
// root override. Export-level because tests and the demo assert on it.
func ResolveLogPath(path string) string {
	expanded := expandPercentVars(path)
	if root := os.Getenv(changelogRootEnv); root != "" {
		return filepath.Join(root, filepath.Base(expanded))
	}
	return expanded
}

// expandPercentVars expands Windows-style %VAR% references, which os.ExpandEnv
// does not understand (it only knows $VAR and ${VAR}). Both forms are accepted
// so a path can be written whichever way reads best in YAML.
func expandPercentVars(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); {
		if p[i] == '%' {
			end := strings.IndexByte(p[i+1:], '%')
			if end >= 0 {
				name := p[i+1 : i+1+end]
				if v, ok := os.LookupEnv(name); ok && name != "" {
					b.WriteString(v)
					i += end + 2
					continue
				}
			}
		}
		b.WriteByte(p[i])
		i++
	}
	return os.ExpandEnv(b.String())
}
