package engine

import (
	"fmt"
	"testing"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

func testBaseline() *baseline.Baseline {
	return &baseline.Baseline{
		Version: "v1",
		Checks: []baseline.Check{
			{ID: "c-priv", Severity: model.SeverityHigh, Kinds: []string{"Pod"},
				Condition: baseline.Condition{Path: "spec.privileged", Op: "eq", Value: true}},
			{ID: "a-nonroot", Severity: model.SeverityMedium, Kinds: []string{"Pod", "Deployment"},
				Condition: baseline.Condition{Path: "spec.securityContext.runAsNonRoot", Op: "ne", Value: true}},
			{ID: "b-image-tag", Severity: model.SeverityLow, Kinds: []string{"*"},
				Condition: baseline.Condition{Path: "spec.image", Op: "regex", Value: `:latest$`}},
		},
	}
}

func testObjects(n int) []model.Object {
	objs := make([]model.Object, 0, n)
	for i := 0; i < n; i++ {
		kind := "Pod"
		if i%3 == 0 {
			kind = "Deployment"
		}
		objs = append(objs, model.Object{
			Ref: model.ObjectRef{Kind: kind, Namespace: fmt.Sprintf("ns%d", i%5), Name: fmt.Sprintf("obj-%03d", i)},
			Fields: map[string]any{
				"spec": map[string]any{
					"privileged": i%7 == 0,
					"image":      fmt.Sprintf("repo/app:%d", i),
				},
			},
		})
	}
	return objs
}

// 并发确定性：不同并发度、多次运行，结论必须逐条一致。
func TestConcurrentDeterminism(t *testing.T) {
	bl := testBaseline()
	objs := testObjects(200)
	var want *Result
	for _, conc := range []int{1, 2, 4, 8, 32} {
		for run := 0; run < 3; run++ {
			got, err := Run(objs, bl, Options{Concurrency: conc})
			if err != nil {
				t.Fatal(err)
			}
			if want == nil {
				want = got
				continue
			}
			if len(got.Findings) != len(want.Findings) {
				t.Fatalf("conc=%d run=%d: finding count differs", conc, run)
			}
			for i := range want.Findings {
				if got.Findings[i] != want.Findings[i] {
					t.Fatalf("conc=%d run=%d: finding %d differs:\n%+v\n%+v", conc, run, i, got.Findings[i], want.Findings[i])
				}
			}
		}
	}
	if want == nil || len(want.Findings) == 0 {
		t.Fatal("expected findings")
	}
}

// 结论排序：按 (CheckID, 对象键)。
func TestFindingOrder(t *testing.T) {
	res, err := Run(testObjects(10), testBaseline(), Options{Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(res.Findings); i++ {
		a, b := res.Findings[i-1], res.Findings[i]
		if a.CheckID > b.CheckID || (a.CheckID == b.CheckID && a.Ref.Key() >= b.Ref.Key()) {
			t.Fatalf("findings not sorted at %d: %v >= %v", i, a, b)
		}
	}
}
