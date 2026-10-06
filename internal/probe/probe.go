// Package probe is the thin, platform-shaped layer between whodunit and the
// machine. Everything here is read-only.
//
// On Windows the real implementation talks to advapi32. On any other OS the
// stub reports ErrUnsupported, which keeps `go vet ./...` and the test suite
// green on the Linux CI runners.
package probe

import (
	"errors"
	"os"
	"time"
)

// ErrUnsupported means "this platform cannot answer this question". Callers
// must degrade the evidence grade, never fabricate a value.
var ErrUnsupported = errors.New("not supported on this platform")

// Registry is the read-only view of the Windows registry that sources need.
type Registry interface {
	// GetString returns the value rendered as a string, and whether it exists.
	GetString(hive, path, name string) (string, bool, error)
	// KeyLastWrite returns the last write time of a key. This is the workhorse
	// behind grade C evidence: it survives tool uninstalls and log wipes.
	KeyLastWrite(hive, path string) (time.Time, error)
	// KeyExists reports whether a key exists.
	KeyExists(hive, path string) (bool, error)
}

// NewRegistry returns the registry implementation for the running platform.
//
// If WHODUNIT_REGISTRY_FIXTURE points at a readable JSON file, that fixture is
// returned instead of the live hive. This is a testing/demo hook only; in
// normal use the variable is unset and the real registry is read.
func NewRegistry() Registry {
	if path := os.Getenv("WHODUNIT_REGISTRY_FIXTURE"); path != "" {
		if reg, err := loadFixtureRegistry(path); err == nil {
			return reg
		}
	}
	return newRegistry()
}

// SplitHive breaks "HKLM\SOFTWARE\Policies" into ("HKLM", "SOFTWARE\Policies").
func SplitHive(path string) (hive, rest string) {
	for i := 0; i < len(path); i++ {
		if path[i] == '\\' || path[i] == '/' {
			return path[:i], path[i+1:]
		}
	}
	return path, ""
}
