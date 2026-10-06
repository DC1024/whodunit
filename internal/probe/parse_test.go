package probe

import "testing"

func TestParseServiceState(t *testing.T) {
	out := `
SERVICE_NAME: wuauserv
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_PRESHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
`
	state, ok := ParseServiceState(out)
	if !ok || state != "RUNNING" {
		t.Errorf("ParseServiceState = %q, %v; want RUNNING, true", state, ok)
	}
}

func TestParseServiceStateStopped(t *testing.T) {
	out := "SERVICE_NAME: spooler\n        STATE              : 1  STOPPED\n"
	if state, ok := ParseServiceState(out); !ok || state != "STOPPED" {
		t.Errorf("ParseServiceState = %q, %v; want STOPPED, true", state, ok)
	}
}

func TestParseServiceStateMissing(t *testing.T) {
	if _, ok := ParseServiceState("[SC] EnumQueryServicesStatus:OpenService FAILED 1060"); ok {
		t.Error("a failed query must not be parsed as a state")
	}
}

func TestParseServiceStartType(t *testing.T) {
	cases := map[string]string{
		"        START_TYPE         : 4   DISABLED\n":              "DISABLED",
		"        START_TYPE         : 2   AUTO_START\n":            "AUTO_START",
		"        START_TYPE         : 2   AUTO_START  (DELAYED)\n": "AUTO_START",
		"        START_TYPE         : 3   DEMAND_START\n":          "DEMAND_START",
	}
	for out, want := range cases {
		if got, ok := ParseServiceStartType(out); !ok || got != want {
			t.Errorf("ParseServiceStartType(%q) = %q, %v; want %q", out, got, ok, want)
		}
	}
}

// The whole reason this parser exists: the header of the unavailable section
// also contains the word "available", so a naive substring search reports
// every state as supported.
const powercfgEnglish = `The following sleep states are available on this system:
    Standby (S0 Low Power Idle) Network Connected
    Fast Startup

The following sleep states are not available on this system:
    Standby (S1)
    Standby (S2)
    Hibernate
    Standby (S3)
`

func TestParseSleepAvailabilityAvailable(t *testing.T) {
	if available, found := ParseSleepAvailability(powercfgEnglish, "standby"); !found || !available {
		t.Errorf("standby = available %v found %v; want true, true", available, found)
	}
}

func TestParseSleepAvailabilityTrap(t *testing.T) {
	available, found := ParseSleepAvailability(powercfgEnglish, "hibernate")
	if !found {
		t.Fatal("hibernate is listed; found must be true")
	}
	if available {
		t.Error("hibernate appears under the 'not available' heading; must not be reported as available")
	}
}

func TestParseSleepAvailabilityChinese(t *testing.T) {
	out := "此系统上有以下睡眠状态:\n    待机 (S0 低电源待机) 已连接网络\n\n" +
		"此系统上没有以下睡眠状态:\n    待机 (S1)\n    休眠\n"
	if available, found := ParseSleepAvailability(out, "hibernate"); !found || available {
		t.Errorf("hibernate = available %v found %v; want false, true", available, found)
	}
	if available, found := ParseSleepAvailability(out, "standby"); !found || !available {
		t.Errorf("standby = available %v found %v; want true, true", available, found)
	}
}

func TestParseSleepAvailabilityUnknownState(t *testing.T) {
	if _, found := ParseSleepAvailability(powercfgEnglish, "teleportation"); found {
		t.Error("a state that is never mentioned must report found=false, not an opinion")
	}
}

func TestParsePrinters(t *testing.T) {
	out := "\ufeffHP LaserJet\tTrue\tFalse\r\n" +
		"Fax\tFalse\tTrue\r\n" +
		"\r\n" +
		"Broken row without tabs\r\n"
	printers := ParsePrinters(NormalizePrinterOutput(out))
	if len(printers) != 2 {
		t.Fatalf("parsed %d printers, want 2 (BOM, blank and malformed lines skipped)", len(printers))
	}
	if printers[0].Name != "HP LaserJet" || !printers[0].Default || printers[0].WorkOffline {
		t.Errorf("first printer = %+v", printers[0])
	}
	if printers[1].Name != "Fax" || printers[1].Default || !printers[1].WorkOffline {
		t.Errorf("second printer = %+v", printers[1])
	}
}

// A Chinese printer name only survives if the command forced UTF-8 output;
// this pins the parser side of that contract.
func TestParsePrintersKeepsUnicodeNames(t *testing.T) {
	out := "办公室打印机\tTrue\tFalse\n"
	printers := ParsePrinters(out)
	if len(printers) != 1 || printers[0].Name != "办公室打印机" {
		t.Errorf("parsed %+v, want one printer named 办公室打印机", printers)
	}
}
