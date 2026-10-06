package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

const baselineFile = `
versions:
  - version: v1
    checks:
      - id: no-privileged
        severity: high
        kinds: [Pod]
        condition: {path: spec.privileged, op: eq, value: true}
        message: privileged container
  - version: v2
    checks:
      - id: no-privileged
        severity: critical
        kinds: [Pod]
        condition: {path: spec.privileged, op: eq, value: true}
        message: privileged container
      - id: require-run-as-non-root
        severity: medium
        kinds: [Pod]
        condition: {path: spec.securityContext.runAsNonRoot, op: ne, value: true}
        message: must run as non-root
`

func writeBaseline(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(p, []byte(baselineFile), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func pod(privileged bool, runAsNonRoot any) model.Object {
	fields := map[string]any{
		"kind":     "Pod",
		"metadata": map[string]any{"name": "p", "namespace": "ns"},
		"spec":     map[string]any{"privileged": privileged},
	}
	if runAsNonRoot != nil {
		fields["spec"].(map[string]any)["securityContext"] = map[string]any{"runAsNonRoot": runAsNonRoot}
	}
	return model.Object{
		Ref:    model.ObjectRef{Kind: "Pod", Namespace: "ns", Name: "p"},
		Fields: fields,
	}
}

// 版本演进：同一对象在不同版本下结论不同；旧版本仍可加载求值（历史可解释）。
func TestVersionEvolution(t *testing.T) {
	p := writeBaseline(t)
	v1, err := LoadFile(p, "v1")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := LoadFile(p, "v2")
	if err != nil {
		t.Fatal(err)
	}
	obj := pod(true, nil)

	if len(v1.Checks) != 1 || len(v2.Checks) != 2 {
		t.Fatalf("unexpected check counts: v1=%d v2=%d", len(v1.Checks), len(v2.Checks))
	}
	// v1 中严重度为 high，v2 中同一检查升级为 critical。
	if v1.Checks[0].Severity != model.SeverityHigh || v2.Checks[0].Severity != model.SeverityCritical {
		t.Fatalf("severity evolution not preserved")
	}
	// v2 新增检查对缺失 runAsNonRoot 的对象判违规。
	pass, err := Eval(v2.Checks[1], obj)
	if err != nil {
		t.Fatal(err)
	}
	if pass {
		t.Fatal("expected fail for missing runAsNonRoot under v2")
	}
	// 同一检查在 v1 下求值依然可用，结论不受 v2 影响。
	pass, err = Eval(v1.Checks[0], obj)
	if err != nil {
		t.Fatal(err)
	}
	if pass {
		t.Fatal("expected fail for privileged pod under v1")
	}
}

// 未知版本必须报错并列出可用版本。
func TestUnknownVersion(t *testing.T) {
	p := writeBaseline(t)
	if _, err := LoadFile(p, "v9"); err == nil {
		t.Fatal("expected error for unknown version")
	}
}

// 条件操作语义。
func TestConditionOps(t *testing.T) {
	obj := model.Object{Fields: map[string]any{
		"spec": map[string]any{
			"replicas": 3,
			"image":    "nginx:1.25",
			"ports":    []any{80, 443},
		},
	}}
	cases := []struct {
		cond Condition
		want bool // pass?
	}{
		{Condition{Path: "spec.replicas", Op: "eq", Value: 3}, false},
		{Condition{Path: "spec.replicas", Op: "gt", Value: 5}, true},
		{Condition{Path: "spec.replicas", Op: "lt", Value: 5}, false},
		{Condition{Path: "spec.image", Op: "regex", Value: `^nginx:`}, false},
		{Condition{Path: "spec.image", Op: "contains", Value: "1.25"}, false},
		{Condition{Path: "spec.ports", Op: "contains", Value: 8080}, true},
		{Condition{Path: "spec.ports", Op: "contains", Value: 443}, false},
		{Condition{Path: "spec.missing", Op: "exists"}, true},
		{Condition{Path: "spec.missing", Op: "not-exists"}, false},
		{Condition{Path: "spec.image", Op: "in", Value: []any{"busybox", "nginx:1.25"}}, false},
	}
	for i, c := range cases {
		got, err := Eval(Check{ID: "t", Condition: c.cond}, obj)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got != c.want {
			t.Fatalf("case %d (%+v): got pass=%v want %v", i, c.cond, got, c.want)
		}
	}
}
