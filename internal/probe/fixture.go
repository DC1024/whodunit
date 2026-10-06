package probe

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// This file is a testing aid, not a production path.
//
// Grade A means "the culprit's own record named it". Proving that end to end
// normally requires a machine with a debloat tool actually installed and having
// changed a setting — impractical in CI and undesirable on a working PC. So
// whodunit accepts a JSON description of the registry behind the
// WHODUNIT_REGISTRY_FIXTURE environment variable. When set, NewRegistry returns
// the fixture instead of the live hive; when unset (always, in normal use) the
// real registry is read.
//
// It is the sibling of WHODUNIT_CHANGELOG_ROOT in files.go: together they let a
// rule author — or `make demo` — reproduce an A-grade attribution byte for byte
// on any machine, which is also how the report fixtures stay honest.

type fixtureValue struct {
	Hive  string `json:"hive"`
	Path  string `json:"path"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type fixtureLastWrite struct {
	Hive string `json:"hive"`
	Path string `json:"path"`
	At   string `json:"at"`
}

type fixtureDoc struct {
	Keys      []string           `json:"keys"`
	Values    []fixtureValue     `json:"values"`
	LastWrite []fixtureLastWrite `json:"last_write"`
}

type fixtureRegistry struct {
	keys   map[string]bool
	values map[string]string
	times  map[string]time.Time
}

func loadFixtureRegistry(path string) (Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc fixtureDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	f := &fixtureRegistry{
		keys:   map[string]bool{},
		values: map[string]string{},
		times:  map[string]time.Time{},
	}
	for _, k := range doc.Keys {
		f.keys[fixtureKey(k)] = true
	}
	for _, v := range doc.Values {
		key := fixtureKey(v.Hive + `\` + v.Path)
		f.keys[key] = true
		f.values[key+`|`+strings.ToLower(v.Name)] = v.Value
	}
	for _, lw := range doc.LastWrite {
		at, err := time.Parse(time.RFC3339, lw.At)
		if err != nil {
			continue
		}
		f.times[fixtureKey(lw.Hive+`\`+lw.Path)] = at.UTC()
	}
	return f, nil
}

func (f *fixtureRegistry) GetString(hive, path, name string) (string, bool, error) {
	v, ok := f.values[fixtureKey(hive+`\`+path)+`|`+strings.ToLower(name)]
	return v, ok, nil
}

func (f *fixtureRegistry) KeyLastWrite(hive, path string) (time.Time, error) {
	at, ok := f.times[fixtureKey(hive+`\`+path)]
	if !ok {
		return time.Time{}, nil
	}
	return at, nil
}

func (f *fixtureRegistry) KeyExists(hive, path string) (bool, error) {
	key := fixtureKey(hive + `\` + path)
	if f.keys[key] {
		return true, nil
	}
	prefix := key + `|`
	for k := range f.values {
		if strings.HasPrefix(k, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// fixtureKey normalizes separators and case so a fixture can be written with
// either slash style without the lookup silently missing.
func fixtureKey(s string) string {
	s = strings.ReplaceAll(s, "/", `\`)
	return strings.ToLower(s)
}
