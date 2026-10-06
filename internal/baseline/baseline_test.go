package baseline

import (
	"strings"
	"testing"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
)

func TestBuiltinRegistryVersionsAndEvolution(t *testing.T) {
	reg, err := BuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	vs := reg.Versions()
	if len(vs) != 2 || vs[0] != "1" || vs[1] != "2" {
		t.Fatalf("versions = %v want [1 2]", vs)
	}
	v1, _ := reg.Get("1")
	v2, _ := reg.Get("2")
	var c1, c2 *Check
	for _, c := range v1.Checks {
		if c.ID == CheckCPURequests+":"+string(object.KindDeployment) {
			c1 = c
		}
	}
	for _, c := range v2.Checks {
		if c.ID == CheckCPURequests+":"+string(object.KindDeployment) {
			c2 = c
		}
	}
	if c1 == nil || c2 == nil {
		t.Fatal("CPU check missing")
	}
	if c1.Severity != finding.SeverityMedium {
		t.Fatalf("v1 severity = %s want medium", c1.Severity)
	}
	if c2.Severity != finding.SeverityHigh {
		t.Fatalf("v2 severity = %s want high", c2.Severity)
	}
	// v2 adds the namespace label check; v1 never has it.
	var hasV1, hasV2 bool
	for _, c := range v1.Checks {
		if c.ID == CheckNamespaceLabels {
			hasV1 = true
		}
	}
	for _, c := range v2.Checks {
		if c.ID == CheckNamespaceLabels {
			hasV2 = true
		}
	}
	if hasV1 {
		t.Fatal("C-004 must not exist in v1")
	}
	if !hasV2 {
		t.Fatal("C-004 must exist in v2")
	}
}

func TestPublishedBaselineIsImmutable(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&Baseline{Version: "9", Checks: []*Check{
		{ID: "X", Kind: object.KindPod, Severity: finding.SeverityLow},
	}}); err != nil {
		t.Fatal(err)
	}
	err := reg.Register(&Baseline{Version: "9", Checks: []*Check{
		{ID: "X", Kind: object.KindPod, Severity: finding.SeverityHigh},
	}})
	if err == nil {
		t.Fatal("expected immutability violation error")
	}
}

func TestCheckEvaluation(t *testing.T) {
	priv := &Check{
		ID: "t", Kind: object.KindPod, Severity: finding.SeverityHigh,
		Conditions: []Condition{
			{Field: FieldSelector{"container:securityContext.privileged"}, Op: OpEq, Value: "true"},
		},
	}
	violating := &object.Object{Key: object.Key{Kind: object.KindPod, Name: "p"},
		Spec: map[string]any{"containers": []any{
			map[string]any{"name": "c", "securityContext": map[string]any{"privileged": true}},
		}}}
	clean := &object.Object{Key: object.Key{Kind: object.KindPod, Name: "p"},
		Spec: map[string]any{"containers": []any{
			map[string]any{"name": "c", "securityContext": map[string]any{"privileged": false}},
		}}}
	if ok, _ := priv.Evaluate(violating); !ok {
		t.Fatal("privileged pod must violate")
	}
	if ok, _ := priv.Evaluate(clean); ok {
		t.Fatal("non-privileged pod must not violate")
	}

	// Resource pseudo-field: missing cpu request violates OpMissing (the
	// violation modeled by built-in C-003); a present request passes.
	cpu := &Check{Kind: object.KindPod,
		Conditions: []Condition{{Field: FieldSelector{"resource:requests.cpu"}, Op: OpMissing}}}
	if ok, _ := cpu.Evaluate(clean); !ok {
		t.Fatal("missing cpu request must violate missing check")
	}
	withReq := &object.Object{Key: object.Key{Kind: object.KindPod},
		Spec: map[string]any{"containers": []any{
			map[string]any{"name": "c", "resources": map[string]any{
				"requests": map[string]any{"cpu": "100m"}}},
		}}}
	if ok, _ := cpu.Evaluate(withReq); ok {
		t.Fatal("present cpu request must satisfy missing check")
	}

	// labels.missing condition for namespaces.
	owner := &Check{Kind: object.KindNamespace,
		Conditions: []Condition{{Field: FieldSelector{"labels.owner"}, Op: OpMissing}}}
	ns := &object.Object{Key: object.Key{Kind: object.KindNamespace, Name: "default"}, Labels: map[string]string{}}
	if ok, _ := owner.Evaluate(ns); !ok {
		t.Fatal("namespace without owner label must violate")
	}
	ns.Labels["owner"] = "team"
	if ok, _ := owner.Evaluate(ns); ok {
		t.Fatal("namespace with owner label must pass")
	}
}

func TestHostNetworkCheck(t *testing.T) {
	c := &Check{Kind: object.KindPod,
		Conditions: []Condition{{Field: FieldSelector{"spec.hostNetwork"}, Op: OpEq, Value: "true"}}}
	o := &object.Object{Key: object.Key{Kind: object.KindPod}, Spec: map[string]any{"hostNetwork": true}}
	ok, msg := c.Evaluate(o)
	if !ok || !strings.Contains(msg, "") {
		t.Fatalf("hostNetwork true must violate, msg=%q", msg)
	}
}
