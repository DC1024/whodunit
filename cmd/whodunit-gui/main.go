// Command whodunit-gui is whodunit with a window.
//
// It is deliberately not a widget toolkit. whodunit ships as one static binary
// built with CGO_ENABLED=0, and every native GUI option would cost that: they
// need cgo, a C toolchain, or a multi-megabyte dependency tree. So the GUI is
// a tiny local HTTP server plus a page compiled into the binary with go:embed.
// Double-clicking the exe opens your own browser on 127.0.0.1, and closing the
// browser tab does not leave anything running behind a firewall - the server
// never listens on anything but loopback, and it exits when you close it.
//
// Everything the CLI can do is reachable here, and the report is the same
// report: the bytes come out of report.Markdown, so the GUI cannot drift from
// what you would paste into a forum thread.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/DC1024/whodunit/internal/engine"
	"github.com/DC1024/whodunit/internal/model"
	"github.com/DC1024/whodunit/internal/probe"
	"github.com/DC1024/whodunit/internal/report"
	"github.com/DC1024/whodunit/internal/rules"
	"github.com/DC1024/whodunit/internal/sources"
)

//go:embed ui.html
var ui embed.FS

var version = "dev"

type result struct {
	Findings []*model.Finding `json:"findings"`
	Markdown string           `json:"markdown"`
	Lang     string           `json:"lang"`
	Matched  int              `json:"matched"`
	Message  string           `json:"message,omitempty"`
}

type ruleItem struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Symptom []string `json:"symptom"`
}

func main() {
	port := flag.Int("port", 0, "port to serve on (0 picks a free one)")
	noOpen := flag.Bool("no-open", false, "do not launch a browser")
	host := flag.String("host", "127.0.0.1", "address to bind (loopback only by design)")
	flag.Parse()

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot start:", err)
		os.Exit(2)
	}
	addr := ln.Addr().String()
	url := "http://" + addr + "/"

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveUI)
	mux.HandleFunc("/api/rules", handleRules)
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/api/why", handleWhy)
	mux.HandleFunc("/api/quit", handleQuit)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	}()

	fmt.Println("whodunit", version)
	fmt.Println("serving on", url)
	fmt.Println("close this window to stop")

	if !*noOpen {
		openBrowser(url)
	}

	// Ctrl+C in the console is the documented way out; so is the Quit button,
	// which is there because a -H windowsgui build has no console to press it in.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := ui.ReadFile("ui.html")
	if err != nil {
		http.Error(w, "ui missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func decodeLang(r *http.Request) string {
	if r.Method == http.MethodPost {
		var body struct {
			Lang string `json:"lang"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.Lang != "" {
			return normalizeLang(body.Lang)
		}
	}
	return normalizeLang(r.URL.Query().Get("lang"))
}

func normalizeLang(l string) string {
	if strings.EqualFold(l, "en") {
		return "en"
	}
	return "zh"
}

func handleRules(w http.ResponseWriter, r *http.Request) {
	lang := decodeLang(r)
	rs, errs := rules.LoadEmbedded()
	if len(rs) == 0 {
		writeErr(w, "no rules available", errs)
		return
	}
	items := make([]ruleItem, 0, len(rs))
	for _, rr := range rs {
		items = append(items, ruleItem{ID: rr.ID, Title: rr.LocalTitle(lang), Symptom: rr.Symptom})
	}
	writeJSON(w, items)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	lang := decodeLang(r)
	rs, errs := rules.LoadEmbedded()
	if len(rs) == 0 {
		writeErr(w, "no rules available", errs)
		return
	}
	writeResult(w, rs, lang, "")
}

func handleWhy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Query string `json:"query"`
		Lang  string `json:"lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	lang := normalizeLang(body.Lang)
	q := strings.TrimSpace(body.Query)
	if q == "" {
		writeJSON(w, result{Lang: lang, Message: model.Pick(lang,
			"describe the symptom first, e.g. \"26H2 not offered\"",
			"先描述症状，例如「26H2 装不上」")})
		return
	}
	all, errs := rules.LoadEmbedded()
	if len(all) == 0 {
		writeErr(w, "no rules available", errs)
		return
	}
	var matched []*rules.Rule
	for _, rr := range all {
		if rr.Matches(q) {
			matched = append(matched, rr)
		}
	}
	if len(matched) == 0 {
		writeJSON(w, result{Lang: lang, Matched: 0, Message: model.Pick(lang,
			"no rule matches that symptom yet; run a full scan instead, or add a rule",
			"没有规则匹配这个症状；可以先跑一次全量扫描，或者自己加一条规则")})
		return
	}
	writeResult(w, matched, lang, q)
}

// writeResult runs the investigation and renders the same markdown the CLI
// would print, so the GUI report and a pasted forum report are identical.
func writeResult(w http.ResponseWriter, rs []*rules.Rule, lang, query string) {
	if runtime.GOOS != "windows" {
		writeJSON(w, result{Lang: lang, Message: model.Pick(lang,
			"whodunit only investigates Windows machines; this one is "+runtime.GOOS,
			"whodunit 只排查 Windows 机器，当前是 "+runtime.GOOS)})
		return
	}
	eng := engine.New(probe.NewRegistry(), probe.NewCommands(), sources.New(), time.Now(), lang)
	findings, err := eng.EvaluateAll(rs)
	if err != nil {
		http.Error(w, "investigation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	host, _ := os.Hostname()
	h := report.Header{Version: version, Generated: time.Now(), Hostname: host, OS: runtime.GOOS + "/" + runtime.GOARCH}
	md := report.Markdown(h, findings, lang)

	matched := 0
	for _, f := range findings {
		if f.Detected {
			matched++
		}
	}
	writeJSON(w, result{Findings: findings, Markdown: md, Lang: lang, Matched: matched})
}

// handleQuit exists because the release build uses -H windowsgui: there is no
// console window to close, so the page needs a way to stop the server.
func handleQuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}()
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, msg string, errs []error) {
	for _, e := range errs {
		log.Println("rule error:", e)
	}
	http.Error(w, msg, http.StatusInternalServerError)
}
