# whodunit

**Find out who changed a Windows setting, and when.**

Windows records the value. It never records the author. So when a feature
update silently stops appearing, or hibernate disappears from the power menu,
you are left with a value that somebody wrote and no way to ask who.

`whodunit` answers that. One command, one symptom, one attribution — and when
it cannot name the culprit, it says so instead of guessing.

[中文文档](README.zh-CN.md)

---

## What this is not

Being explicit about boundaries saves everyone time:

- **It is not a health checker.** It does not scan your PC for "issues" and
  print a score. Tools that do that already exist in abundance.
- **It is not a tweaker.** It never writes anything. It prints the revert
  commands; you decide whether to run them.
- **It is not ProcMon.** ProcMon has to be running *before* the change happens.
  You are here because it was not.
- **It is not a forensic suite.** RegRipper and friends are for investigators
  working from a disk image. This is for the person sitting at the machine.

## Why not just use an existing tool

| Tool | What it does | Why it does not solve this |
|---|---|---|
| Process Monitor / RegFromApp | live registry write capture | must be running before the change; useless after the fact |
| Regshot / SysTracer | snapshot diff | tells you *what* changed, never *who*; needs a pre-change snapshot |
| Sysinternals Policy Analyzer | group policy comparison | manual, no attribution, no plain-language output |
| winutil / Sophia Script / privacy.sexy | apply tweaks | these are what *caused* your problem, not what explains it |
| `gpresult /h` | dump resultant policy | covers policy only, and leaves the reading to you |

The gap: **after-the-fact attribution of a configuration change, on a machine
that was never prepared for an investigation.**

## Install

Download the archive for your PC from the
[releases page](https://github.com/DC1024/whodunit/releases). It holds two
binaries, both single static files with no installer and no data files:

| Binary | For |
|---|---|
| `whodunit.exe` | the command line — scripts, logon tasks, `-json` output |
| `whodunit-gui.exe` | double-click, and it opens the report in your browser |

The GUI is not a widget toolkit. Every native option would need cgo or a large
dependency tree, and the point of whodunit is one static `CGO_ENABLED=0` file —
so it is a loopback HTTP server with the page compiled in, and it never listens
on anything but `127.0.0.1`. It shows the same report the CLI prints, generated
by the same function, so the window and a pasted forum thread cannot disagree.

Only Windows builds are published. CI does cross-compile linux/amd64, but that
target exists to keep the non-Windows stubs honest, not to be downloaded —
whodunit investigates Windows machines.

No administrator rights are needed to *read*. Each archive ships a `.sha256`
per binary; check it.

Project page: <https://whodunit.app.workbuddy.host/>

```powershell
whodunit why "26H2 not offered"
```

Or build it yourself:

```bash
go build ./cmd/whodunit
```

## Usage

```
whodunit rules                 list shipped rules
whodunit scan                  run every rule and report what was found
whodunit why "<symptom>"       match rules by symptom, then attribute
```

Flags: `-json` for machine-readable output, `-rules <dir>` to load your own
rule files instead of the built-in set, `-lang <code>` to pick the report
language (`auto` / `en` / `zh`; default `auto`, which follows the system
locale — an English shell gets an English report, a Chinese Windows stays
Chinese).

Every rule ships both Chinese and English copy, and the report *chrome* —
headings, field labels (`observed` / `subject` / `attributed to`), the evidence
table, the "nothing matched" note and the revert steps — follows the same flag.
So `-lang en` produces a fully English report (and `-lang zh` a fully Chinese
one), with no half-translated middle, ready to paste into a forum thread.

Exit codes: `0` nothing matched, `1` something matched, `2` usage or runtime
error. That makes it usable in a script or a logon task.

### Example

```
## [DETECTED] wufb-feature-update-blocked

**Feature updates are blocked by policy (26H2 will not install)**

- observed: `DisableWindowsUpdateAccess=1`
- subject: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
- **attributed to: Winhance (evidence A, tool_fingerprint)**

| grade | source | what it proves |
|---|---|---|
| A | tool_fingerprint | Winhance's own change history names this setting |
| C | registry_lastwrite | the key was last written at 2026-10-04 11:10:19 |
| D | event_audit | no write audit available for this value |

Details:

- **A / tool_fingerprint** — Winhance's own change history names this setting
  Found `C:\ProgramData\Winhance\Logs\ChangeHistory.txt`. Its change history
  records this setting, so the tool itself confirms it made the change:
  `[SET] HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableWindowsUpdateAccess`.

Revert (printed only; whodunit does not run these):

1. Remove the "disable access to Windows Update" policy value
   ```
   reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /f
   ```
```

Grade A is not a promise on a slide — it is a code path that reads the tool's
own receipt and quotes the line. `demo/` reproduces the whole chain against a
fixture, on any machine, with no debloat tool installed.

## Evidence grades

Every piece of evidence carries a grade, and the grade is a promise.

| Grade | Means | Typical source |
|---|---|---|
| **A** | the actor is named by its own record | a tool's own change log, read from disk |
| **B** | a strong lead: the tool is here and does exactly this | install traces, fingerprints |
| **C** | time only — we know when, not who | registry key `FILETIME` |
| **D** | state only — even the time is unavailable | no source could answer |

When the best available grade is C, the report says `unknown actor`. It does
not promote a guess to a fact. That is the whole point of the project.

Grade A requires a line in the culprit's own log that names *this* setting. A
log that exists but mentions something else stays grade B — presence is not a
confession.

## Rules and fingerprints are data

Adding a check means adding a YAML file — see [CONTRIBUTING.md](CONTRIBUTING.md).
No Go code, no rebuild of the engine.

Shipped rules:

| Rule | Symptom |
|---|---|
| `wufb-feature-update-blocked` | feature updates (26H2 and friends) never appear |
| `sleep-hibernate-disabled` | hibernate missing, lid-close behaviour wrong |
| `default-printer-hijacked` | the default printer keeps changing by itself |

## Limitations

- **A-grade hits are the exception, not the rule.** Most machines have no
  change log to read, so most attributions will be B or C. The grading exists
  so that is honest.
- **Policies can come back.** If an MDM or a scheduled task re-applies a value,
  deleting the key fixes it for fifteen minutes. Check `policy_origin` first.
- **Windows only.** On other platforms it reports "skipped" rather than
  inventing an answer.
- **Fingerprints cover a handful of tools.** The shipped set knows about
  Winhance, ShutUp10 and friends; a debloat tool not in
  `internal/sources/fingerprints/tools.yaml` cannot be named, no matter how
  obvious it is. Adding one is a YAML edit — pull requests welcome.

## License

MIT. See [LICENSE](LICENSE).
