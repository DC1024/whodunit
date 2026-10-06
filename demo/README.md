# The A-grade demo

whodunit's whole reason to exist is **grade A**: naming the culprit, not just the
symptom. Grade A is only honest when it comes from the culprit's *own* record —
a debloat tool that writes "I changed X" to its own log is naming itself, and no
amount of registry snooping can do that.

This directory reproduces that end to end, on any machine, without installing a
debloat tool.

## The scenario

A machine has `DisableWindowsUpdateAccess = 1` under the Windows Update policy
key. Feature updates (26H2-class) no longer appear in Windows Update. The user
did not do this and has no memory of a tool doing it.

The registry records the *value* and a timestamp, but never the author. That is
where a naive tool stops, at grade C: "something changed this, at some point."

## What whodunit does differently

1. A rule detects the symptom from the current state (`wufb-feature-update-blocked`).
2. The `tool_fingerprint` source looks for known culprits. Winhance is installed
   here (its `HKCU\Software\Winhance` marker is present) → that alone is grade B:
   "this tool was here and does this kind of thing."
3. Then whodunit **reads Winhance's own change history** —
   `%ProgramData%\Winhance\Logs\ChangeHistory.txt` — and finds a line naming the
   exact setting. The tool is quoting itself → grade A.

## Run it

```sh
go build -o dist/whodunit-windows-amd64.exe ./cmd/whodunit
./demo/run.sh              # Chinese
LANG_CODE=en ./demo/run.sh # English
```

## How the fixture works

Two environment variables swap the machine for a committed fixture. Without
them, nothing changes: whodunit reads the live registry, as always.

| Variable | Effect |
|---|---|
| `WHODUNIT_REGISTRY_FIXTURE` | Read `registry.json` as the registry instead of the live hive |
| `WHODUNIT_CHANGELOG_ROOT` | Resolve `%ProgramData%\...\ChangeHistory.txt` to `ChangeHistory.txt` in this directory |

- `registry.json` — the policy value is set, Winhance's marker key exists, and
  the key carries a FILETIME, so you can see the weaker evidence chain too.
- `ChangeHistory.txt` — modeled on Winhance Release 27's real format: session
  headers, `[SET]` lines with before/after values, and the UI path that made the
  change.

## What you should see

The report ends with:

```
- **attributed to: Winhance (evidence A, tool_fingerprint)**
```

and the evidence detail quotes the tool's own line:

```
[SET] HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableWindowsUpdateAccess
```

`expected-output.txt` is the full captured run.

## The honesty check

Delete the matching line from `ChangeHistory.txt` (or point at a log that names
a *different* setting) and re-run. Grade A disappears and the finding falls back
to grade B — "this tool is installed here and changes this kind of setting" — with
no fabricated actor. The mechanism is only allowed to say "Winhance did it" when
Winhance actually says so.