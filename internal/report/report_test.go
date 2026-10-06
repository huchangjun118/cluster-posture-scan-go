package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/report"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/scan"
)

// buildEngineResult runs a small full scan directly to obtain a Result.
func buildResult(t *testing.T, workers int, stateDir string) *scan.Result {
	t.Helper()
	dir := t.TempDir()
	snapFile := dir + "/snap.json"
	content := `[
	  {"kind":"Pod","metadata":{"name":"a","namespace":"ns"},"spec":{"hostNetwork":true,"containers":[{"name":"c"}]}},
	  {"kind":"Service","metadata":{"name":"s","namespace":"ns"},"spec":{"type":"NodePort"}}
	]`
	if err := writeFile(snapFile, content); err != nil {
		t.Fatal(err)
	}
	snap, err := object.NewLoader(dir, workers).Load()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := baseline.BuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.NewEngine(reg, nil, scan.Config{
		Workers: workers, StateDir: stateDir, BaselineVer: "1",
		AsOf: mustTime("2026-01-01T00:00:00Z"),
	}).FullScan(snap)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestByteStableAcrossRunsAndConcurrency(t *testing.T) {
	var first string
	for i, w := range []int{1, 2, 7, 16} {
		res := buildResult(t, w, t.TempDir())
		var buf bytes.Buffer
		if err := report.Write(&buf, res, report.Options{Format: report.FormatJSON}); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if i == 0 {
			first = out
			continue
		}
		if out != first {
			t.Fatalf("report bytes differ at workers=%d", w)
		}
	}
	if !strings.Contains(first, `"severity"`) || !strings.Contains(first, `"by_severity"`) {
		t.Fatal("report missing expected sections")
	}
	// Findings must be ordered by severity rank desc then check id.
	if strings.Index(first, string(finding.SeverityHigh)) > strings.Index(first, string(finding.SeverityMedium)) {
		t.Fatal("findings not ordered by severity descending")
	}
}

func TestSummaryIncludesZeroSeverityBuckets(t *testing.T) {
	res := buildResult(t, 1, t.TempDir())
	var buf bytes.Buffer
	if err := report.Write(&buf, res, report.Options{}); err != nil {
		t.Fatal(err)
	}
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if !strings.Contains(buf.String(), `"`+sev+`":`) {
			t.Fatalf("summary missing severity bucket %s", sev)
		}
	}
}
