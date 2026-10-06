package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
)

// Built-in check identifiers.
const (
	CheckPrivileged      = "C-001"
	CheckHostNetwork     = "C-002"
	CheckCPURequests     = "C-003"
	CheckNamespaceLabels = "C-004"
	CheckNodePort        = "C-005"
	CheckAutoMountToken  = "C-006"
)

// workloadKinds are the kinds embedding a pod template/spec.
var workloadKinds = []object.Kind{
	object.KindPod, object.KindDeployment, object.KindStatefulSet,
	object.KindDaemonSet, object.KindJob, object.KindCronJob,
}

// v1Checks is the first published baseline.
func v1Checks() []*Check {
	var checks []*Check
	checks = append(checks, workloadChecks(
		CheckPrivileged,
		"Containers must not run in privileged mode",
		finding.SeverityHigh,
		Condition{Field: FieldSelector{Path: "container:securityContext.privileged"}, Op: OpEq, Value: "true"},
	)...)
	checks = append(checks, workloadChecks(
		CheckHostNetwork,
		"Pods must not share the host network namespace",
		finding.SeverityHigh,
		Condition{Field: FieldSelector{Path: "spec.hostNetwork"}, Op: OpEq, Value: "true"},
	)...)
	checks = append(checks, workloadChecks(
		CheckCPURequests,
		"Every container must declare CPU requests",
		finding.SeverityMedium,
		Condition{Field: FieldSelector{Path: "resource:requests.cpu"}, Op: OpMissing},
	)...)
	checks = append(checks,
		&Check{
			ID:         CheckNodePort,
			Title:      "Services must not expose NodePort",
			Kind:       object.KindService,
			Severity:   finding.SeverityMedium,
			Message:    "Service exposes a NodePort",
			Conditions: []Condition{{Field: FieldSelector{Path: "spec.type"}, Op: OpEq, Value: "NodePort"}},
		},
		&Check{
			ID:       CheckAutoMountToken,
			Title:    "ServiceAccounts must not auto-mount API tokens by default",
			Kind:     object.KindServiceAccount,
			Severity: finding.SeverityLow,
			Message:  "ServiceAccount auto-mounts its API token",
			Conditions: []Condition{
				{Field: FieldSelector{Path: "spec.automountServiceAccountToken"}, Op: OpNe, Value: "false"},
			},
		},
	)
	return checks
}

// v2Checks evolves v1:
//   - C-003 is tightened from medium to high.
//   - new C-004 requires workload namespaces to carry an "owner" label
//     (expressed against Namespace objects).
func v2Checks() []*Check {
	checks := v1Checks()
	out := make([]*Check, 0, len(checks)+1)
	for _, c := range checks {
		cp := *c
		if cp.ID == CheckCPURequests || strings.HasPrefix(cp.ID, CheckCPURequests+":") {
			cp.Severity = finding.SeverityHigh
			cp.Title = "Every container must declare CPU requests (strict)"
		}
		out = append(out, &cp)
	}
	out = append(out, &Check{
		ID:       CheckNamespaceLabels,
		Title:    "Namespaces must declare an owner label",
		Kind:     object.KindNamespace,
		Severity: finding.SeverityMedium,
		Message:  "Namespace is missing the owner label",
		Conditions: []Condition{
			{Field: FieldSelector{Path: "labels.owner"}, Op: OpMissing},
		},
	})
	return out
}

// workloadChecks replicates one check definition across all workload kinds,
// giving each copy an ID suffix by kind (C-001:POD style) is avoided: instead
// the same Check is registered per kind with identical ID is invalid, so the
// caller uses a single Check per kind with ID "<base>:<kind>".
func workloadChecks(baseID, title string, sev finding.Severity, cond Condition) []*Check {
	var out []*Check
	for _, k := range workloadKinds {
		out = append(out, &Check{
			ID:         baseID + ":" + string(k),
			Title:      title,
			Kind:       k,
			Severity:   sev,
			Message:    title,
			Conditions: []Condition{cond},
		})
	}
	return out
}

// BuiltinRegistry constructs a registry populated with built-in baselines:
// version "1" and version "2".
func BuiltinRegistry() (*Registry, error) {
	r := NewRegistry()
	if err := r.Register(&Baseline{Version: "1", Checks: v1Checks()}); err != nil {
		return nil, err
	}
	if err := r.Register(&Baseline{Version: "2", Checks: v2Checks()}); err != nil {
		return nil, err
	}
	return r, nil
}

// checkDigest is a stable identity of a check definition used to detect
// conflicting re-registration.
func checkDigest(c *Check) string {
	b, _ := json.Marshal(struct {
		ID         string           `json:"id"`
		Kind       object.Kind      `json:"kind"`
		Severity   finding.Severity `json:"severity"`
		Title      string           `json:"title"`
		Message    string           `json:"message"`
		Conditions []Condition      `json:"conditions"`
	}{c.ID, c.Kind, c.Severity, c.Title, c.Message, c.Conditions})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
