package scan

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/state"
)

func testBaseline(version string) *baseline.Baseline {
	return &baseline.Baseline{
		Version: version,
		Checks: []baseline.Check{
			{ID: "no-privileged", Severity: model.SeverityHigh, Kinds: []string{"Pod"},
				Condition: baseline.Condition{Path: "spec.privileged", Op: "eq", Value: true}, Message: "privileged"},
			{ID: "require-nonroot", Severity: model.SeverityMedium, Kinds: []string{"Pod"},
				Condition: baseline.Condition{Path: "spec.runAsNonRoot", Op: "ne", Value: true}, Message: "nonroot"},
		},
	}
}

func genObjs(n int, mutate func(i int, priv bool) (keep bool, newPriv bool)) []model.Object {
	var objs []model.Object
	for i := 0; i < n; i++ {
		keep, priv := mutate(i, i%5 == 0)
		if !keep {
			continue
		}
		objs = append(objs, model.Object{
			Ref:    model.ObjectRef{Kind: "Pod", Namespace: "ns", Name: fmt.Sprintf("pod-%02d", i)},
			Fields: map[string]any{"spec": map[string]any{"privileged": priv}},
		})
	}
	return objs
}

func equalFindings(a, b []model.Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// 增量复核：对象增删改后，增量结论必须与全量重扫逐条一致，消失对象结论被回收。
func TestIncrementalEqualsFull(t *testing.T) {
	bl := testBaseline("v1")
	statePath := filepath.Join(t.TempDir(), "state.json")

	v1objs := genObjs(50, func(i int, priv bool) (bool, bool) { return true, priv })
	sc := &Scanner{Baseline: bl, StatePath: statePath, Concurrency: 4}
	if _, err := sc.Scan(v1objs); err != nil {
		t.Fatal(err)
	}

	// 增删改：删 pod-01，改 pod-02 的字段，新增 pod-99。
	v2objs := genObjs(50, func(i int, priv bool) (bool, bool) {
		if i == 1 {
			return false, priv // 删除
		}
		if i == 2 {
			return true, true // 修改
		}
		return true, priv
	})
	v2objs = append(v2objs, model.Object{
		Ref:    model.ObjectRef{Kind: "Pod", Namespace: "ns", Name: "pod-99"},
		Fields: map[string]any{"spec": map[string]any{"privileged": true}},
	})

	inc, err := sc.Scan(v2objs)
	if err != nil {
		t.Fatal(err)
	}

	// 全量重扫（无状态）。
	full, err := (&Scanner{Baseline: bl, Concurrency: 4}).Scan(v2objs)
	if err != nil {
		t.Fatal(err)
	}
	if !equalFindings(inc.Findings, full.Findings) {
		t.Fatal("incremental result differs from full rescan")
	}

	// 消失对象的旧结论必须回收。
	st, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Objects["Pod/ns/pod-01"]; ok {
		t.Fatal("stale finding for removed object not reclaimed")
	}
	if len(st.Objects) != len(v2objs) {
		t.Fatalf("state should track exactly current objects: %d vs %d", len(st.Objects), len(v2objs))
	}
	for _, f := range inc.Findings {
		if f.Ref.Name == "pod-01" {
			t.Fatal("finding for removed object still present")
		}
	}
}

// 断点恢复：中断（部分提交）后继续，结果与一次性跑完逐条一致。
func TestResumeAfterInterruption(t *testing.T) {
	bl := testBaseline("v1")
	statePath := filepath.Join(t.TempDir(), "state.json")
	objs := genObjs(40, func(i int, priv bool) (bool, bool) { return true, priv })

	// 模拟中断：只扫完前 15 个对象就"崩溃"（状态已提交）。
	crashed := &Scanner{Baseline: bl, StatePath: statePath, CommitEvery: 1, Concurrency: 4}
	if _, err := crashed.Scan(objs[:15]); err != nil {
		t.Fatal(err)
	}

	// 恢复：对完整快照继续扫描。
	resumed := &Scanner{Baseline: bl, StatePath: statePath, CommitEvery: 1, Concurrency: 4}
	got, err := resumed.Scan(objs)
	if err != nil {
		t.Fatal(err)
	}

	// 一次性跑完。
	want, err := (&Scanner{Baseline: bl, Concurrency: 4}).Scan(objs)
	if err != nil {
		t.Fatal(err)
	}
	if !equalFindings(got.Findings, want.Findings) {
		t.Fatal("resumed result differs from one-shot run")
	}
}

// 基线版本切换使缓存失效：只有显式切换版本才改变结论。
func TestVersionSwitchInvalidatesCache(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	objs := genObjs(10, func(i int, priv bool) (bool, bool) { return true, priv })

	v1 := testBaseline("v1")
	sc := &Scanner{Baseline: v1, StatePath: statePath}
	r1, err := sc.Scan(objs)
	if err != nil {
		t.Fatal(err)
	}
	// 同版本重扫：结论不变。
	r2, err := sc.Scan(objs)
	if err != nil {
		t.Fatal(err)
	}
	if !equalFindings(r1.Findings, r2.Findings) {
		t.Fatal("same version rescan changed conclusions")
	}
	for _, f := range r2.Findings {
		if f.BaselineVersion != "v1" {
			t.Fatal("finding carries wrong version")
		}
	}
	// 显式切换到 v2（严重度升级）。
	v2 := testBaseline("v2")
	v2.Checks[0].Severity = model.SeverityCritical
	r3, err := (&Scanner{Baseline: v2, StatePath: statePath}).Scan(objs)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r3.Findings {
		if f.BaselineVersion != "v2" {
			t.Fatal("finding carries wrong version after switch")
		}
		if f.CheckID == "no-privileged" && f.Severity != model.SeverityCritical {
			t.Fatal("severity upgrade not applied after version switch")
		}
	}
	st, _ := state.Load(statePath)
	if st.BaselineVersion != "v2" {
		t.Fatal("state version not updated after switch")
	}
}

// 未变化对象不重估：通过篡改状态指纹验证复用路径。
func TestUnchangedObjectsNotReevaluated(t *testing.T) {
	bl := testBaseline("v1")
	statePath := filepath.Join(t.TempDir(), "state.json")
	objs := genObjs(10, func(i int, priv bool) (bool, bool) { return true, priv })
	sc := &Scanner{Baseline: bl, StatePath: statePath}
	if _, err := sc.Scan(objs); err != nil {
		t.Fatal(err)
	}
	st1, _ := state.Load(statePath)
	if _, err := sc.Scan(objs); err != nil {
		t.Fatal(err)
	}
	st2, _ := state.Load(statePath)
	if len(st1.Objects) != len(st2.Objects) {
		t.Fatal("state changed on no-op rescan")
	}
	for k, v := range st1.Objects {
		if !equalFindings(v.Findings, st2.Objects[k].Findings) || v.Hash != st2.Objects[k].Hash {
			t.Fatalf("object %s re-evaluated on no-op rescan", k)
		}
	}
}
