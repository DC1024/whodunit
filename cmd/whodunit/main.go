// Command whodunit answers one question: who changed this Windows setting,
// and when.
//
// It is deliberately narrow. It is not a health checker, not an optimizer, and
// not a tweaker: those categories already have better tools. Every subcommand
// here ends in an attribution attempt, or says plainly that it cannot make one.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/DC1024/whodunit/internal/engine"
	"github.com/DC1024/whodunit/internal/model"
	"github.com/DC1024/whodunit/internal/probe"
	"github.com/DC1024/whodunit/internal/report"
	"github.com/DC1024/whodunit/internal/rules"
	"github.com/DC1024/whodunit/internal/sources"
)

// version is stamped by the release workflow with -ldflags.
var version = "dev"

const usageText = `whodunit - find out who changed a Windows setting, and when

usage:
  whodunit rules                 list shipped rules
  whodunit scan                  run every rule and report what was found
  whodunit why "<symptom>"       match rules by symptom, then attribute

flags:
  -json          emit JSON instead of markdown
  -rules <dir>   load rules from a directory instead of the built-in set
  -lang <code>   report language: auto | en | zh (default auto)
  -version       print version and exit

exit codes:
  0  nothing matched
  1  at least one rule matched
  2  usage or runtime error

whodunit only reads. It prints revert commands; it never runs them.`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usageText)
		return 0
	case "-version", "--version", "version":
		fmt.Fprintf(stdout, "whodunit %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return 0
	case "rules":
		return cmdRules(args[1:], stdout, stderr)
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "why":
		return cmdWhy(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s\n", args[0], usageText)
		return 2
	}
}

// knownFlags and valueFlags drive hoistFlags below.
var (
	knownFlags = map[string]bool{
		"-json": true, "--json": true,
		"-rules": true, "--rules": true,
		"-lang": true, "--lang": true,
	}
	valueFlags = map[string]bool{
		"-rules": true, "--rules": true,
		"-lang": true, "--lang": true,
	}
)

// hoistFlags moves known flags in front of the free-text query.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `why "26h2" -json` would silently be read as one long query and the -json
// flag would be ignored. Users put flags last; accept it.
func hoistFlags(args []string) []string {
	var flagsArgs, text []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		key := a
		inlineValue := false
		if j := strings.Index(a, "="); j > 0 {
			key = a[:j]
			inlineValue = true
		}
		if knownFlags[key] {
			flagsArgs = append(flagsArgs, a)
			if !inlineValue && valueFlags[key] && i+1 < len(args) {
				i++
				flagsArgs = append(flagsArgs, args[i])
			}
			continue
		}
		text = append(text, a)
	}
	return append(flagsArgs, text...)
}

func newFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *bool, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON instead of markdown")
	fs.Bool("version", false, "print version")
	lang := fs.String("lang", "auto", "report language: auto | en | zh")
	return fs, jsonOut, lang
}

// resolveLang turns the -lang flag into a concrete language code. "auto"
// inspects common locale env vars and falls back to zh; anything unrecognised
// also falls back to zh so a typo never produces an empty report.
func resolveLang(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "en", "english":
		return "en"
	case "zh", "cn", "chinese":
		return "zh"
	default:
		return detectLang()
	}
}

// detectLang reads the process locale. On a Chinese Windows box LANG is usually
// unset, so the default report stays Chinese; an English shell on CI or Linux
// gets an English report without an explicit flag.
func detectLang() string {
	for _, v := range []string{"LANG", "LC_ALL", "LANGUAGE", "LC_MESSAGES"} {
		val := strings.ToLower(os.Getenv(v))
		if val == "" {
			continue
		}
		if strings.HasPrefix(val, "en") || strings.Contains(val, "en_us") || strings.Contains(val, "en_gb") {
			return "en"
		}
	}
	return "zh"
}

func loadRules(dir string, stderr io.Writer) ([]*rules.Rule, bool) {
	if dir == "" {
		rs, errs := rules.LoadEmbedded()
		reportParseErrors(errs, stderr)
		return rs, len(rs) > 0
	}
	rs, errs := rules.Load(dir)
	reportParseErrors(errs, stderr)
	return rs, len(rs) > 0
}

func reportParseErrors(errs []error, stderr io.Writer) {
	for _, err := range errs {
		fmt.Fprintf(stderr, "rule error: %v\n", err)
	}
}

func cmdRules(args []string, stdout, stderr io.Writer) int {
	fs, jsonOut, langFlag := newFlagSet("rules", stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	lang := resolveLang(*langFlag)
	rs, ok := loadRules("", stderr)
	if !ok {
		fmt.Fprintln(stderr, "no rules available")
		return 2
	}
	if *jsonOut {
		ids := make([]string, 0, len(rs))
		for _, r := range rs {
			ids = append(ids, r.ID)
		}
		out, _ := report.JSON(ids)
		fmt.Fprintln(stdout, string(out))
		return 0
	}
	for _, r := range rs {
		fmt.Fprintf(stdout, "%-32s %s\n", r.ID, r.LocalTitle(lang))
		if len(r.Symptom) > 0 {
			fmt.Fprintf(stdout, "%-32s try: whodunit why \"%s\"\n", "", r.Symptom[0])
		}
	}
	return 0
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs, jsonOut, langFlag := newFlagSet("scan", stderr)
	rulesDir := fs.String("rules", "", "directory of rule YAML files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	lang := resolveLang(*langFlag)
	rs, ok := loadRules(*rulesDir, stderr)
	if !ok {
		fmt.Fprintln(stderr, "no rules available")
		return 2
	}
	findings, code := investigate(rs, *jsonOut, lang, stdout, stderr)
	if code != 0 {
		return code
	}
	emit(findings, *jsonOut, stdout, stderr)
	return exitCodeFor(findings)
}

func cmdWhy(args []string, stdout, stderr io.Writer) int {
	fs, jsonOut, langFlag := newFlagSet("why", stderr)
	rulesDir := fs.String("rules", "", "directory of rule YAML files")
	if err := fs.Parse(hoistFlags(args)); err != nil {
		return 2
	}
	lang := resolveLang(*langFlag)
	query := strings.Join(fs.Args(), " ")
	if strings.TrimSpace(query) == "" {
		fmt.Fprintln(stderr, `why needs a symptom, e.g. why "26H2 not offered"`)
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	all, ok := loadRules(*rulesDir, stderr)
	if !ok {
		fmt.Fprintln(stderr, "no rules available")
		return 2
	}
	var matched []*rules.Rule
	for _, r := range all {
		if r.Matches(query) {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		fmt.Fprintf(stderr, "no rule matches %q\n", query)
		fmt.Fprintln(stderr, "run 'whodunit rules' to see what is covered")
		return 0
	}
	findings, code := investigate(matched, *jsonOut, lang, stdout, stderr)
	if code != 0 {
		return code
	}
	emit(findings, *jsonOut, stdout, stderr)
	return exitCodeFor(findings)
}

func investigate(rs []*rules.Rule, jsonOut bool, lang string, stdout, stderr io.Writer) ([]*model.Finding, int) {
	reg := probe.NewRegistry()
	eng := engine.New(reg, probe.NewCommands(), sources.New(), time.Now(), lang)
	findings, err := eng.EvaluateAll(rs)
	if err != nil {
		fmt.Fprintf(stderr, "investigation failed: %v\n", err)
		return nil, 2
	}
	return findings, 0
}

func emit(findings []*model.Finding, jsonOut bool, stdout, stderr io.Writer) {
	if jsonOut {
		out, err := report.JSON(findings)
		if err != nil {
			fmt.Fprintf(stderr, "marshal: %v\n", err)
			return
		}
		fmt.Fprintln(stdout, string(out))
		return
	}
	host, _ := os.Hostname()
	h := report.Header{
		Version:   version,
		Generated: time.Now(),
		Hostname:  host,
		OS:        runtime.GOOS + "/" + runtime.GOARCH,
	}
	fmt.Fprint(stdout, report.Markdown(h, findings))
}

func exitCodeFor(findings []*model.Finding) int {
	for _, f := range findings {
		if f.Detected {
			return 1
		}
	}
	return 0
}
