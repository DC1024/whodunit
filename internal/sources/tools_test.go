package sources

import (
	"testing"

	"github.com/DC1024/whodunit/internal/model"
)

// The subject needles are what decide whether a tool's own log "names" a
// setting. Too loose and unrelated lines become confessions; too strict and a
// real match is missed. Pin both edges.
func TestSubjectNeedles(t *testing.T) {
	reg := model.Subject{
		Kind:  "registry_key",
		Path:  `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`,
		Value: "DisableWindowsUpdateAccess",
	}
	got := subjectNeedles(reg)
	if len(got) != 2 {
		t.Fatalf("needles = %v, want path + long value", got)
	}
	if got[0] != `hklm\software\policies\microsoft\windows\windowsupdate` {
		t.Errorf("path needle = %q", got[0])
	}
	if got[1] != "disablewindowsupdateaccess" {
		t.Errorf("value needle = %q", got[1])
	}
}

// A short value name is not specific enough to be a second needle: "AU" would
// match half a log file. Only the path is required then.
func TestSubjectNeedlesSkipsShortValue(t *testing.T) {
	s := model.Subject{Kind: "registry_key", Path: `HKLM\SOFTWARE\X`, Value: "AU"}
	if got := subjectNeedles(s); len(got) != 1 {
		t.Errorf("needles = %v, want just the path", got)
	}
}

// A non-registry subject falls back to RegistryPath so a service rule can still
// be matched against a tool's log.
func TestSubjectNeedlesFallsBackToRegistryPath(t *testing.T) {
	s := model.Subject{Kind: "service", Path: "wuauserv", RegistryPath: `HKLM\SYSTEM\CurrentControlSet\Services\wuauserv`}
	got := subjectNeedles(s)
	if len(got) == 0 || got[0] != `hklm\system\currentcontrolset\services\wuauserv` {
		t.Errorf("needles = %v, want RegistryPath", got)
	}
}

func TestFirstMentioningLine(t *testing.T) {
	log := "Winhance Change History\n" +
		"[SET] HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\DisableWindowsUpdateAccess\n" +
		"      0 -> 1\n"
	line, ok := firstMentioningLine(log, []string{
		`hklm\software\policies\microsoft\windows\windowsupdate`,
		"disablewindowsupdateaccess",
	})
	if !ok {
		t.Fatal("expected a matching line")
	}
	if line != `[SET] HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableWindowsUpdateAccess` {
		t.Errorf("line = %q", line)
	}
}

// Forward slashes in a log must still match a backslash path: tools are
// inconsistent about it and the user should not care.
func TestFirstMentioningLineNormalizesSlashes(t *testing.T) {
	log := "SET HKCU/Software/Winhance/Advanced : 0 -> 1\n"
	_, ok := firstMentioningLine(log, []string{`hkcu\software\winhance\advanced`})
	if !ok {
		t.Error("forward-slash path should match a backslash needle")
	}
}

func TestFirstMentioningLineRejectsDifferentSetting(t *testing.T) {
	log := "[SET] HKCU\\Software\\Explorer\\TaskbarSmallIcons : 0 -> 1\n"
	if _, ok := firstMentioningLine(log, []string{
		`hklm\software\policies\microsoft\windows\windowsupdate`,
		"disablewindowsupdateaccess",
	}); ok {
		t.Error("a line naming a different setting must not match")
	}
}
