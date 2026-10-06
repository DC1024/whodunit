package probe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveLogPathExpandsPercentVars(t *testing.T) {
	t.Setenv("ProgramData", `C:\ProgramData`)
	got := ResolveLogPath(`%ProgramData%\Winhance\Logs\ChangeHistory.txt`)
	want := `C:\ProgramData\Winhance\Logs\ChangeHistory.txt`
	if got != want {
		t.Errorf("ResolveLogPath = %q, want %q", got, want)
	}
}

func TestResolveLogPathHonorsFixtureRoot(t *testing.T) {
	t.Setenv("ProgramData", `C:\ProgramData`)
	t.Setenv(changelogRootEnv, filepath.FromSlash("/fixtures"))
	got := ResolveLogPath(`%ProgramData%\Winhance\Logs\ChangeHistory.txt`)
	want := filepath.Join(filepath.FromSlash("/fixtures"), "ChangeHistory.txt")
	if got != want {
		t.Errorf("ResolveLogPath with root = %q, want %q", got, want)
	}
}

// Guards the CI case: on Linux %ProgramData% is undefined, so the path keeps its
// Windows backslashes. filepath.Base would return the whole string there, which
// silently dropped the demo from grade A to grade C.
func TestResolveLogPathFixtureRootWithoutWindowsVars(t *testing.T) {
	t.Setenv("ProgramData", "")
	os.Unsetenv("ProgramData")
	t.Setenv(changelogRootEnv, filepath.FromSlash("/fixtures"))
	got := ResolveLogPath(`%ProgramData%\Winhance\Logs\ChangeHistory.txt`)
	want := filepath.Join(filepath.FromSlash("/fixtures"), "ChangeHistory.txt")
	if got != want {
		t.Errorf("ResolveLogPath unresolved root = %q, want %q", got, want)
	}
}

func TestBaseNameSplitsBothSeparators(t *testing.T) {
	cases := []struct{ in, want string }{
		{`%ProgramData%\Winhance\Logs\ChangeHistory.txt`, "ChangeHistory.txt"},
		{`C:/Logs/ChangeHistory.txt`, "ChangeHistory.txt"},
		{"ChangeHistory.txt", "ChangeHistory.txt"},
		{`C:\Logs\`, ""},
	}
	for _, c := range cases {
		if got := baseName(c.in); got != c.want {
			t.Errorf("baseName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveLogPathExpandsDollarVars(t *testing.T) {
	t.Setenv("APPDATA", `C:\Users\x\AppData\Roaming`)
	got := ResolveLogPath(`$APPDATA\O&O\ShutUp10++\ShutUp10.cfg`)
	want := `C:\Users\x\AppData\Roaming\O&O\ShutUp10++\ShutUp10.cfg`
	if got != want {
		t.Errorf("ResolveLogPath $-form = %q, want %q", got, want)
	}
}

func TestFileReaderMissingIsACleanMiss(t *testing.T) {
	f := NewFiles()
	if !f.Available() {
		t.Fatal("file reader must be available on every platform")
	}
	_, exists, err := f.Read(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil {
		t.Fatalf("missing file must not be an error, got %v", err)
	}
	if exists {
		t.Error("missing file must report exists=false")
	}
}

func TestFileReaderReturnsContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ChangeHistory.txt")
	if err := os.WriteFile(p, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	content, exists, err := NewFiles().Read(p)
	if err != nil || !exists {
		t.Fatalf("read = (%q, %v, %v), want content and exists", content, exists, err)
	}
	if content != "hello\n" {
		t.Errorf("content = %q, want hello", content)
	}
}

// The fixture is what makes an A-grade demo reproducible off a clean machine.
// If it stops loading, the demo silently falls back to the live registry and
// reports "clean" — a confusing failure, so pin it here.
func TestFixtureRegistryServesKeysValuesAndTimes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "registry.json")
	doc := `{
	  "keys": ["HKCU\\Software\\Winhance"],
	  "values": [{"hive":"HKLM","path":"SOFTWARE\\Policies\\X","name":"NoAutoUpdate","value":"1"}],
	  "last_write": [{"hive":"HKLM","path":"SOFTWARE\\Policies\\X","at":"2026-10-04T11:10:19Z"}]
	}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := loadFixtureRegistry(p)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}

	ok, err := reg.KeyExists("HKCU", `Software\Winhance`)
	if err != nil || !ok {
		t.Errorf("KeyExists = (%v, %v), want true", ok, err)
	}
	// A value implies its key exists even when not listed under "keys".
	ok, err = reg.KeyExists("HKLM", `SOFTWARE\Policies\X`)
	if err != nil || !ok {
		t.Errorf("KeyExists(values path) = (%v, %v), want true", ok, err)
	}
	v, got, err := reg.GetString("HKLM", `SOFTWARE\Policies\X`, "NoAutoUpdate")
	if err != nil || !got || v != "1" {
		t.Errorf("GetString = (%q, %v, %v), want (1, true, nil)", v, got, err)
	}
	at, err := reg.KeyLastWrite("HKLM", `SOFTWARE\Policies\X`)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 4, 11, 10, 19, 0, time.UTC)
	if !at.Equal(want) {
		t.Errorf("KeyLastWrite = %s, want %s", at, want)
	}
}

func TestNewRegistryUsesFixtureWhenSet(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(p, []byte(`{"keys":["HKCU\\Software\\FixtureOnly"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHODUNIT_REGISTRY_FIXTURE", p)
	reg := NewRegistry()
	ok, err := reg.KeyExists("HKCU", `Software\FixtureOnly`)
	if err != nil || !ok {
		t.Fatalf("fixture-backed registry did not answer: (%v, %v)", ok, err)
	}
}
