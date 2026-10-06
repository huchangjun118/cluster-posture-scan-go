package report

import (
	"testing"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/engine"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

func testResult() *engine.Result {
	return &engine.Result{
		BaselineVersion: "v1",
		Findings: []model.Finding{
			{CheckID: "a", BaselineVersion: "v1", Ref: model.ObjectRef{Kind: "Pod", Name: "p1"}, Severity: model.SeverityHigh, Status: model.StatusFail, Message: "m"},
			{CheckID: "a", BaselineVersion: "v1", Ref: model.ObjectRef{Kind: "Pod", Name: "p2"}, Severity: model.SeverityHigh, Status: model.StatusPass},
			{CheckID: "b", BaselineVersion: "v1", Ref: model.ObjectRef{Kind: "Pod", Name: "p1"}, Severity: model.SeverityCritical, Status: model.StatusExempt},
			{CheckID: "b", BaselineVersion: "v1", Ref: model.ObjectRef{Kind: "Pod", Name: "p2"}, Severity: model.SeverityCritical, Status: model.StatusFail, Message: "m"},
		},
	}
}

// 同一结论渲染多次必须逐字节一致。
func TestRenderByteStable(t *testing.T) {
	res := testResult()
	first, err := Render(res)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		got, err := Render(res)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(first) {
			t.Fatalf("render %d differs", i)
		}
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize(testResult().Findings)
	if s.Critical != 1 || s.High != 1 || s.Pass != 1 || s.Exempt != 1 || s.Medium != 0 || s.Low != 0 {
		t.Fatalf("unexpected summary: %+v", s)
	}
}

// 空结论输出 [] 而非 null，保证字节稳定。
func TestRenderEmpty(t *testing.T) {
	data, err := Render(&engine.Result{BaselineVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(data), `"findings": []`) {
		t.Fatalf("empty findings should render as []: %s", data)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
