package probe

import (
	"strings"
)

// Commands runs read-only external tools.
//
// Some questions cannot be answered from the registry: which sleep states the
// firmware actually supports, whether a service is running right now, what the
// default printer is. Those come from built-in Windows commands. Everything
// here is a query; nothing mutates.
type Commands interface {
	// Output runs a command and returns its combined stdout.
	Output(name string, args ...string) (string, error)
	// Available reports whether external commands can run at all.
	Available() bool
}

// ParseServiceState reads the STATE field out of `sc query` output.
//
// sc.exe is not localized, so the state word is always English:
// "STATE              : 4  RUNNING".
func ParseServiceState(out string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "STATE") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		// Take the last field: "STATE : 4 RUNNING" ends with the state word.
		// Some states carry flags after it, so stop at the first all-caps token
		// that looks like a state instead of blindly taking the last one.
		for _, f := range fields {
			switch strings.ToUpper(f) {
			case "RUNNING", "STOPPED", "START_PENDING", "STOP_PENDING", "PAUSED":
				return strings.ToUpper(f), true
			}
		}
	}
	return "", false
}

// ParseServiceStartType reads START_TYPE out of `sc qc` output, e.g.
// "START_TYPE         : 4   DISABLED".
func ParseServiceStartType(out string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "START_TYPE") {
			continue
		}
		idx := strings.Index(trimmed, ":")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(trimmed[idx+1:])
		// Strip a leading numeric code, then drop any parenthesised qualifier
		// such as "(DELAYED)" so AUTO_START and AUTO_START (DELAYED) agree.
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if len(fields) > 1 && isAllDigits(fields[0]) {
			fields = fields[1:]
		}
		return strings.ToUpper(fields[0]), true
	}
	return "", false
}

// knownSleepStates maps the state name used in rule YAML onto the tokens that
// can appear in `powercfg /a` output, in English and in Chinese.
var knownSleepStates = map[string][]string{
	"hibernate":   {"hibernate", "休眠"},
	"standby":     {"standby", "待机"},
	"s0":          {"s0", "s0"},
	"faststartup": {"fast startup", "快速启动"},
}

// ParseSleepAvailability reports whether `powercfg /a` lists the given sleep
// state as available. found is false when the state simply is not mentioned,
// which is different from "mentioned as unavailable".
//
// The trap here: the unavailable section header also contains the word
// "available" ("are not available on this system"), so a plain substring test
// would report everything as supported.
func ParseSleepAvailability(out, state string) (available, found bool) {
	tokens, ok := knownSleepStates[strings.ToLower(state)]
	if !ok {
		tokens = []string{strings.ToLower(state)}
	}
	inUnavailableSection := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if isSectionHeader(lower) {
			inUnavailableSection = isUnavailableHeader(lower, line)
			continue
		}
		if matchesTokens(lower, line, tokens) {
			// "Hibernate" listed under the unavailable heading, e.g.
			// "Standby (S3) ... The system firmware does not support..."
			return !inUnavailableSection, true
		}
	}
	return false, false
}

func isSectionHeader(lower string) bool {
	return strings.Contains(lower, "sleep states") || strings.Contains(lower, "睡眠状态")
}

func isUnavailableHeader(lower, original string) bool {
	for _, neg := range []string{"not available", "unavailable", "不可用", "没有以下", "不支持"} {
		if strings.Contains(lower, neg) || strings.Contains(original, neg) {
			return true
		}
	}
	return false
}

func matchesTokens(lower, original string, tokens []string) bool {
	for _, t := range tokens {
		if strings.Contains(lower, strings.ToLower(t)) || strings.Contains(original, t) {
			return true
		}
	}
	return false
}

// PrinterInfo is one line of printer inventory.
type PrinterInfo struct {
	Name        string
	Default     bool
	WorkOffline bool
}

// ParsePrinters reads tab-separated printer rows produced by the inventory
// command in commands_windows.go. Unparseable lines are skipped rather than
// aborting: one weird printer name should not lose the rest.
func ParsePrinters(out string) []PrinterInfo {
	var outList []PrinterInfo
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 3 {
			continue
		}
		outList = append(outList, PrinterInfo{
			Name:        strings.TrimSpace(cols[0]),
			Default:     strings.EqualFold(strings.TrimSpace(cols[1]), "true"),
			WorkOffline: strings.EqualFold(strings.TrimSpace(cols[2]), "true"),
		})
	}
	return outList
}

// ServiceQuery returns the arguments for querying a service's live state.
func ServiceQuery(name string) []string { return []string{"query", name} }

// ServiceConfig returns the arguments for querying how a service is set to start.
func ServiceConfig(name string) []string { return []string{"qc", name} }

// SleepStates returns the arguments for listing supported sleep states.
func SleepStates() []string { return []string{"/a"} }

// PrinterInventory returns a command that dumps one tab-separated row per
// printer. UTF-8 is forced because PowerShell 5.1 otherwise writes Chinese
// printer names using the console code page and they arrive as mojibake.
func PrinterInventory() (string, []string) {
	script := "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " +
		"Get-CimInstance -ClassName Win32_Printer | " +
		"ForEach-Object { '{0}`t{1}`t{2}' -f $_.Name, $_.Default, $_.WorkOffline }"
	return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", script}
}

// NormalizePrinterOutput strips a UTF-8 BOM if the shell emitted one.
func NormalizePrinterOutput(s string) string {
	return strings.TrimPrefix(s, "\ufeff")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
