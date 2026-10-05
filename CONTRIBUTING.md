# Contributing

The shortest path to a useful contribution here is **a rule**, not code.

## Add a rule

Drop one YAML file into `internal/rules/builtin/`. It is compiled into the
binary, so it ships with the next release and requires no code change.

```yaml
id: my-rule-id                 # kebab-case, unique
title: 一句话说清这是什么现象   # shown as the finding heading
severity: warn                 # info | warn | high
symptom:                       # what users type after `whodunit why`
  - 关键词
  - keyword in english

detect:
  kind: registry               # only "registry" is implemented today
  checks:
    - path: 'HKLM\SOFTWARE\Policies\Example'
      name: SomeValue
      equals: '1'
      note: 这个值意味着什么     # printed as "observed"
      required: false

blame:
  subject:
    kind: registry_key
    path: 'HKLM\SOFTWARE\Policies\Example'
    value: SomeValue
  sources:                     # strongest first; defaults to all
    - tool_fingerprint
    - registry_lastwrite
    - policy_origin
    - event_audit

fix:
  - desc: 一步能说清的还原动作
    command: reg delete "HKLM\SOFTWARE\Policies\Example" /v SomeValue /f

notes: >-
  说清楚这意味着什么、通常是谁写的、以及动手前要注意什么。
```

### Check semantics

- `required: true` — must hit, otherwise the rule is not detected.
- `required: false` — optional; **at least one** optional check must hit.
- Mixing them gives you `AND` over the required ones and `OR` over the rest.
- `exists: true` / `exists: false` checks presence instead of a value. When
  `exists` is set, `equals` is ignored.
- `name` empty means "check the key itself, not a value".

### Writing good rule text

`notes` is the part users actually read. It should say:

1. what the value means,
2. who usually writes it (a tool? a GPO? Windows itself?),
3. what will go wrong if they revert blindly.

Do not write "optimize your system". Do not claim certainty the evidence does
not support.

## Add a tool fingerprint

`internal/sources/fingerprints/tools.yaml`. No Go code needed.

```yaml
  - id: some-tool
    name: Some Tool
    confidence: unverified       # verified only if confirmed on real hardware
    markers:                     # presence => grade B
      - {hive: HKCU, path: 'Software\SomeTool'}
    change_logs:                 # presence => grade A
      - {hive: HKCU, path: 'Software\SomeTool\ChangeHistory'}
    note: >-
      这个工具会改哪些东西，以及怎么有选择地撤回。
```

`confidence` must be `unverified` unless you confirmed the path on a real
machine. Reports print that word, and users rely on it.

## Add an evidence source

New source = new file in `internal/sources/` implementing:

```go
type Source interface {
	Name() string
	Investigate(ctx Context, subject model.Subject) ([]model.Evidence, error)
}
```

Rules:

- **Never fabricate.** If you cannot name the actor, leave `Actor` empty and
  lower the grade. That is a correct result, not a failure.
- **Read-only.** A source must not change machine state.
- **Degrade loudly on non-Windows.** Return `nil` when
  `errors.Is(err, probe.ErrUnsupported)` so CI on Linux stays green.

## Before opening a PR

```bash
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

CI runs the same three, plus a cross-compile for linux and windows.
