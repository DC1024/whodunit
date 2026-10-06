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

Download `whodunit-windows-amd64.exe` from the releases page. It is a single
static binary — no installer, no data files, no administrator rights required
to *read*.

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
- **attributed to: Winhance, 2026-09-03 07:41:22 (evidence A, tool_fingerprint)**

| grade | source | what it proves |
|---|---|---|
| A | tool_fingerprint | Winhance keeps a change history on this machine |
| C | registry_lastwrite | the key was last written at 2026-09-03 07:41:22 |
| D | event_audit | no write audit available for this value |

Revert (printed only; whodunit does not run these):

1. Remove the "disable access to Windows Update" policy value
   ```
   reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /f
   ```
```

## Evidence grades

Every piece of evidence carries a grade, and the grade is a promise.

| Grade | Means | Typical source |
|---|---|---|
| **A** | the actor is named by its own record | a tool's change history or log |
| **B** | a strong lead: the tool is here and does exactly this | install traces, fingerprints |
| **C** | time only — we know when, not who | registry key `FILETIME` |
| **D** | state only — even the time is unavailable | no source could answer |

When the best available grade is C, the report says `unknown actor`. It does
not promote a guess to a fact. That is the whole point of the project.

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
- **Rule text is currently Chinese.** The author's reports are written for
  Chinese-speaking users first; translations are welcome as pull requests.

## License

MIT. See [LICENSE](LICENSE).
