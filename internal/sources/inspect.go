package sources

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DC1024/whodunit/internal/model"
	"github.com/DC1024/whodunit/internal/probe"
)

// registryLastWrite answers "when did this change" from the key's own
// FILETIME. No snapshot and no audit policy is required, so it works on a
// machine that was never prepared for an investigation. It cannot name the
// actor, so it tops out at grade C.
type registryLastWrite struct{}

func NewRegistryLastWrite() Source { return registryLastWrite{} }

func (registryLastWrite) Name() string { return "registry_lastwrite" }

func (registryLastWrite) Investigate(ctx Context, subject model.Subject) ([]model.Evidence, error) {
	// A service or a power setting is still configured somewhere on disk, and
	// that key carries a FILETIME. Subjects declare RegistryPath to point at
	// it; without one there is nothing to timestamp.
	path := subject.Path
	if subject.Kind != "registry_key" {
		path = subject.RegistryPath
	}
	if path == "" {
		return nil, nil
	}
	hive, rest := probe.SplitHive(path)
	at, err := ctx.Registry.KeyLastWrite(hive, rest)
	if err != nil {
		if errors.Is(err, probe.ErrUnsupported) {
			return nil, nil
		}
		// A missing key is not an error worth surfacing: the rule that asked
		// for it already knows how to handle absence.
		return nil, nil
	}
	if at.IsZero() {
		return nil, nil
	}
	age := ctx.Now.Sub(at)
	ev := model.Evidence{
		Source:  "registry_lastwrite",
		Grade:   model.GradeC,
		At:      nowOrZero(at),
		Summary: fmt.Sprintf("%s was last written at %s", subject.String(), at.Format("2006-01-02 15:04:05")),
		Detail: fmt.Sprintf(
			"FILETIME of the key, %s before this run. It proves when, never who: "+
				"any process with write access produces the same timestamp.",
			roundDuration(age)),
	}
	return []model.Evidence{ev}, nil
}

// policyOrigin tells the user *which machinery* is enforcing a value: a local
// GPO, an MDM payload, or a bare registry write. That distinction decides the
// fix, because deleting a policy key that an MDM re-applies every 15 minutes
// accomplishes nothing.
type policyOrigin struct{}

func NewPolicyOrigin() Source { return policyOrigin{} }

func (policyOrigin) Name() string { return "policy_origin" }

// MDM-managed settings land under PolicyManager, and the CSP path is kept as
// the human-readable name of the policy.
const policyManagerPath = `SOFTWARE\Microsoft\PolicyManager\current\device`

func (policyOrigin) Investigate(ctx Context, subject model.Subject) ([]model.Evidence, error) {
	if subject.Kind != "registry_key" {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(subject.Path), `\policies\`) {
		return nil, nil
	}
	exists, err := ctx.Registry.KeyExists("HKLM", policyManagerPath)
	if err != nil {
		if errors.Is(err, probe.ErrUnsupported) {
			return nil, nil
		}
		return nil, nil
	}
	// Read the MDM side of the same setting when it exists. We cannot map every
	// Policies key onto its CSP name, so we say what we found and stop there.
	var mdm string
	if exists {
		if v, ok, err := ctx.Registry.GetString("HKLM", policyManagerPath, "Update"); err == nil && ok {
			mdm = v
		}
	}
	if exists {
		return []model.Evidence{{
			Source:  "policy_origin",
			Grade:   model.GradeB,
			Summary: "value lives under Policies, and this machine is MDM-enrolled (PolicyManager present)",
			Detail: "A Policies key backed by PolicyManager is re-applied by the management client. " +
				"Deleting the key is only a temporary fix; remove the policy at the source. " +
				"Cross-check with: gpresult /h report.html" +
				mdmDetail(mdm),
		}}, nil
	}
	return []model.Evidence{{
		Source:  "policy_origin",
		Grade:   model.GradeC,
		Summary: "value lives under Policies, no MDM enrollment detected",
		Detail: "Policies keys are written by group policy, MDM, or any tool with admin rights. " +
			"No PolicyManager hive was found, so a local GPO or a direct registry write is more likely. " +
			"Cross-check with: gpresult /h report.html",
	}}, nil
}

func mdmDetail(v string) string {
	if v == "" {
		return ""
	}
	return fmt.Sprintf(" (PolicyManager\\Update=%s)", v)
}

// eventAudit reports whether the machine could have recorded the actor at all.
// Windows does not log registry writes by default: you need SACL auditing or
// Sysmon running *before* the change happened. Telling the user that is more
// useful than silently returning nothing.
type eventAudit struct{}

func NewEventAudit() Source { return eventAudit{} }

func (eventAudit) Name() string { return "event_audit" }

func (eventAudit) Investigate(ctx Context, subject model.Subject) ([]model.Evidence, error) {
	if subject.Kind != "registry_key" {
		return nil, nil
	}
	// 4657 only appears when "Audit Registry" (SACL) was configured in advance.
	// We do not attempt to query it: doing so reliably needs the event log API
	// and an administrative handle, and a negative result is indistinguishable
	// from "not enabled". Say so instead.
	return []model.Evidence{{
		Source:  "event_audit",
		Grade:   model.GradeD,
		Summary: "no write audit available for this value",
		Detail: "Windows does not record registry writes by default. To catch the next one: " +
			"install Sysmon with a RegSetValue rule, or enable Audit Registry (event 4657) under " +
			"secpol.msc > Advanced Audit Policy > Object Access. Both must run before the change.",
	}}, nil
}

func roundDuration(d time.Duration) string {
	switch {
	case d < 0:
		return "in the future (clock skew)"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
