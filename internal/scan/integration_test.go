package scan_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"encoding/json"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/exemption"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/report"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/scan"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/snapshot"
)

func setupEnv(t *testing.T) (snapDir, baselinePath string) {
	t.Helper()
	dir := t.TempDir()
	snapDir = filepath.Join(dir, "snap")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "pods.yaml"), []byte(`
kind: Pod
metadata: {name: web, namespace: prod}
spec: {privileged: true}
---
kind: Pod
metadata: {name: batch, namespace: prod}
spec: {privileged: false}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath = filepath.Join(dir, "baseline.yaml")
	if err := os.WriteFile(baselinePath, []byte(`
versions:
  - version: v1
    checks:
      - id: no-privileged
        severity: high
        kinds: [Pod]
        condition: {path: spec.privileged, op: eq, value: true}
        message: privileged pod
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return snapDir, baselinePath
}

func runScan(t *testing.T, snapDir, baselinePath string, store *exemption.Store, statePath string) []byte {
	t.Helper()
	objs, err := snapshot.Load(snapDir)
	if err != nil {
		t.Fatal(err)
	}
	bl, err := baseline.LoadFile(baselinePath, "v1")
	if err != nil {
		t.Fatal(err)
	}
	// 与 CLI 一致：只把当前生效的豁免交给扫描器。
	var active []exemption.Exemption
	if store != nil {
		active = store.Active(time.Now())
	}
	sc := &scan.Scanner{Baseline: bl, Exemptions: active, StatePath: statePath, Concurrency: 4}
	res, err := sc.Scan(objs)
	if err != nil {
		t.Fatal(err)
	}
	data, err := report.Render(res)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// 端到端：豁免生效时压制结论，过期后结论恢复；报表逐字节稳定。
func TestEndToEndExemptionExpiry(t *testing.T) {
	snapDir, baselinePath := setupEnv(t)
	statePath := filepath.Join(t.TempDir(), "state.json")

	ex := exemption.Exemption{
		ID:        "e1",
		CheckID:   "no-privileged",
		Ref:       model.ObjectRef{Kind: "Pod", Namespace: "prod", Name: "web"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	store := &exemption.Store{Exemptions: []exemption.Exemption{ex}}
	withEx := runScan(t, snapDir, baselinePath, store, statePath)
	s := report.Summarize(mustParse(t, withEx).Findings)
	if s.Exempt != 1 || s.High != 0 {
		t.Fatalf("active exemption should suppress finding: %+v", s)
	}

	// 豁免过期后同一快照结论恢复为 fail。
	store.Exemptions[0].ExpiresAt = time.Now().Add(-time.Minute)
	expired := runScan(t, snapDir, baselinePath, store, statePath)
	s = report.Summarize(mustParse(t, expired).Findings)
	if s.Exempt != 0 || s.High != 1 {
		t.Fatalf("expired exemption must not suppress: %+v", s)
	}

	// 无豁免、同快照、同版本：两次扫描报表逐字节一致。
	a := runScan(t, snapDir, baselinePath, nil, statePath)
	b := runScan(t, snapDir, baselinePath, nil, "")
	if string(a) != string(b) {
		t.Fatal("report not byte-stable across scans")
	}
	if string(a) != string(expired) {
		t.Fatal("report with expired exemption should equal report without exemption")
	}
}

func mustParse(t *testing.T, data []byte) struct {
	Findings []model.Finding `json:"findings"`
} {
	t.Helper()
	var doc struct {
		Findings []model.Finding `json:"findings"`
	}
	if err := jsonUnmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
