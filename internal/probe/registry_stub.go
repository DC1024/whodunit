//go:build !windows

package probe

import "time"

// registryUnsupported is what every non-Windows build gets. whodunit is a
// Windows tool; on other platforms it must fail loudly and honestly rather
// than report a machine state it never read.
type registryUnsupported struct{}

func newRegistry() Registry { return registryUnsupported{} }

func (registryUnsupported) GetString(hive, path, name string) (string, bool, error) {
	return "", false, ErrUnsupported
}

func (registryUnsupported) KeyLastWrite(hive, path string) (time.Time, error) {
	return time.Time{}, ErrUnsupported
}

func (registryUnsupported) KeyExists(hive, path string) (bool, error) {
	return false, ErrUnsupported
}
