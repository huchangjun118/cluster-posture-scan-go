package scan_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/exemption"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/report"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/scan"
)

var asOf = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// doc is the minimal JSON shape used to build test snapshots.
type doc map[string]any

func pod(name string, privileged bool, cpuReq string) doc {
	sc := map[string]any{}
	if privileged {
		sc["privileged"] = true
	}
	resources := map[string]any{}
	if cpuReq != "" {
		resources["requests"] = map[string]any{"cpu": cpuReq}
	}
	return doc{
		"kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": "ns",
			"labels": map[string]any{}},
		"spec": map[string]any{"containers": []any{
			map[string]any{"name": "c", "securityContext": sc, "resources": resources},
		}},
	}
}

func writeSnapshot(t *testing.T, dir string, docs ...doc) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	arr := make([]any, len(docs))
	for i, d := range docs {
		arr[i] = d
	}
	b, _ := json.MarshalIndent(arr, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "objects.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func loadSnap(t *testing.T, dir string, workers int) *object.Snapshot {
	t.Helper()
	snap, err := object.NewLoader(dir, workers).Load()
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func newReg(t *testing.T) *baseline.Registry {
	t.Helper()
	reg, err := baseline.BuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func findingIDs(r *scan.Result) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.CheckID+"|"+string(f.ObjectKind)+"/"+f.Namespace+"/"+f.Name+":"+string(f.Status))
	}
	sort.Strings(out)
	return out
}

func newStore(t *testing.T, dir string) *exemption.Store {
	t.Helper()
	clk := func() time.Time { return asOf }
	st, err := exemption.OpenStore(filepath.Join(dir, "ex.json"),
		exemption.WithClock(clk), exemption.WithAdmins("admin"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestConcurrencyDeterminism(t *testing.T) {
	dir := t.TempDir()
	writeSnapshot(t, filepath.Join(dir, "snap"),
		pod("a", true, ""), pod("b", false, "100m"), pod("c", true, ""),
		doc{"kind": "Service", "metadata": map[string]any{"name": "s", "namespace": "ns"},
			"spec": map[string]any{"type": "NodePort"}},
	)
	reg := newReg(t)
	var outputs []string
	for _, workers := range []int{1, 2, 3, 8, 32} {
		snap := loadSnap(t, filepath.Join(dir, "snap"), workers)
		stateDir := filepath.Join(dir, "state") // same state dir: second+ runs are resumes
		_ = stateDir
		eng := scan.NewEngine(reg, nil, scan.Config{
			Workers: workers, StateDir: filepath.Join(dir, "fresh", itoa(workers)),
			BaselineVer: "1", AsOf: asOf,
		})
		res, err := eng.FullScan(snap)
		if err != nil {
			t.Fatalf("workers=%d: %v", workers, err)
		}
		var buf bytes.Buffer
		if err := report.Write(&buf, res, report.Options{}); err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, buf.String())
	}
	for i := 1; i < len(outputs); i++ {
		if outputs[i] != outputs[0] {
			t.Fatalf("report differs between worker counts (%d vs 1)", i+1)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestIncrementalEqualsFullAndReclaimsVanished(t *testing.T) {
	dir := t.TempDir()
	snapDir := filepath.Join(dir, "snap")
	stateDir := filepath.Join(dir, "state")
	writeSnapshot(t, snapDir, pod("a", true, ""), pod("b", true, ""))
	reg := newReg(t)

	// Baseline full scan.
	snap1 := loadSnap(t, snapDir, 4)
	eng1 := scan.NewEngine(reg, nil, scan.Config{StateDir: stateDir, BaselineVer: "1", AsOf: asOf, Workers: 4})
	full1, err := eng1.FullScan(snap1)
	if err != nil {
		t.Fatal(err)
	}

	// Snapshot changes: b fixed (no longer privileged), c added privileged, a deleted.
	writeSnapshot(t, snapDir, pod("b", false, "100m"), pod("c", true, ""))
	snap2 := loadSnap(t, snapDir, 4)

	// Incremental review.
	eng2 := scan.NewEngine(reg, nil, scan.Config{StateDir: stateDir, BaselineVer: "1", AsOf: asOf, Workers: 4})
	inc, err := eng2.ReviewIncrementally(snap2)
	if err != nil {
		t.Fatal(err)
	}
	// Reference: fresh full scan of the same snapshot.
	freshDir := filepath.Join(dir, "fresh")
	engRef := scan.NewEngine(reg, nil, scan.Config{StateDir: freshDir, BaselineVer: "1", AsOf: asOf, Workers: 1})
	fullRef, err := engRef.FullScan(snap2)
	if err != nil {
		t.Fatal(err)
	}
	// Compare normalized content: findings (per-item) and summary must match.
	// The incremental flag and the revoked (reclamation) list are operational
	// metadata, not scan conclusions.
	normalize := func(r *scan.Result) string {
		type item struct {
			ID, Name, Status, Severity, Msg, FP, At string
		}
		var items []item
		for _, f := range r.Findings {
			items = append(items, item{f.CheckID, f.Name, string(f.Status), string(f.Severity), f.Message, f.ObjectFP, f.EvaluatedAt})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].ID != items[j].ID {
				return items[i].ID < items[j].ID
			}
			return items[i].Name < items[j].Name
		})
		b, _ := json.Marshal(struct {
			Items []item
			Sum   finding.Summary
		}{items, r.Summary})
		return string(b)
	}
	if normalize(inc) != normalize(fullRef) {
		t.Fatalf("incremental conclusions != full reference\n--- inc ---\n%s\n--- full ---\n%s",
			normalize(inc), normalize(fullRef))
	}
	// a's findings must be reclaimed and reported.
	var reclaimedA bool
	for _, k := range inc.Revoked {
		if k.Name == "a" {
			reclaimedA = true
		}
	}
	if !reclaimedA {
		t.Fatalf("vanished object a findings not reclaimed: %+v", inc.Revoked)
	}
	// Only c remains open for the privileged check.
	var openPriv []string
	for _, f := range inc.Findings {
		if f.CheckID == "C-001:Pod" && f.Status == finding.StatusOpen {
			openPriv = append(openPriv, f.Name)
		}
	}
	if len(openPriv) != 1 || openPriv[0] != "c" {
		t.Fatalf("open privileged = %v want [c]", openPriv)
	}
	_ = full1
}

func TestInterruptionRecoveryEqualsOneShot(t *testing.T) {
	dir := t.TempDir()
	snapDir := filepath.Join(dir, "snap")
	stateDir := filepath.Join(dir, "state")
	writeSnapshot(t, snapDir, pod("a", true, ""), pod("b", true, ""),
		pod("c", false, ""),
		doc{"kind": "Service", "metadata": map[string]any{"name": "sv", "namespace": "ns"},
			"spec": map[string]any{"type": "NodePort"}})
	snap := loadSnap(t, snapDir, 4)
	reg := newReg(t)

	// Reference: uninterrupted single run.
	ref, err := scan.NewEngine(reg, nil, scan.Config{
		StateDir: filepath.Join(dir, "ref"), BaselineVer: "1", AsOf: asOf, Workers: 1,
	}).FullScan(snap)
	if err != nil {
		t.Fatal(err)
	}

	// Interrupted run: fail after 3 units.
	eng := scan.NewEngine(reg, nil, scan.Config{
		StateDir: stateDir, BaselineVer: "1", AsOf: asOf, Workers: 4, CommitEvery: 1,
	}, scan.WithFailureInjection(3))
	if _, err := eng.FullScan(snap); err == nil {
		t.Fatal("expected interruption error")
	}

	// Resume with a fresh engine (same state dir) and complete.
	res2, err := scan.NewEngine(reg, nil, scan.Config{
		StateDir: stateDir, BaselineVer: "1", AsOf: asOf, Workers: 2,
	}).FullScan(snap)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}

	// Findings must be identical and no unit was evaluated twice producing
	// duplicates.
	var b1, b2 bytes.Buffer
	_ = report.Write(&b1, ref, report.Options{})
	_ = report.Write(&b2, res2, report.Options{})
	if b1.String() != b2.String() {
		t.Fatalf("resumed result differs from one-shot\n--- resumed ---\n%s\n--- ref ---\n%s", b2.String(), b1.String())
	}

	// No duplicate findings after resume.
	seen := map[string]int{}
	for _, f := range res2.Findings {
		seen[f.CheckID+"/"+f.Name]++
		if seen[f.CheckID+"/"+f.Name] > 1 {
			t.Fatalf("duplicate finding after resume: %s/%s", f.CheckID, f.Name)
		}
	}
}

func TestExemptionExpiryReopensOnIncrementalReview(t *testing.T) {
	dir := t.TempDir()
	snapDir := filepath.Join(dir, "snap")
	stateDir := filepath.Join(dir, "state")
	writeSnapshot(t, snapDir, pod("a", true, ""))
	snap := loadSnap(t, snapDir, 2)
	reg := newReg(t)
	ex := newStore(t, dir)

	before := asOf
	expiry := asOf.Add(time.Hour)
	e, err := ex.Grant("admin", exemption.Exemption{
		CheckID: "C-001:Pod", ObjectKind: "Pod", Namespace: "ns", Name: "a",
		Reason: "temporary", CreatedAt: before, ExpiresAt: expiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = e

	// Scan while the exemption is active: finding is suppressed.
	r1, err := scan.NewEngine(reg, ex, scan.Config{
		StateDir: stateDir, BaselineVer: "1", AsOf: before, Workers: 2,
	}).FullScan(snap)
	if err != nil {
		t.Fatal(err)
	}
	if statusOf(r1, "C-001:Pod", "a") != finding.StatusSuppressed {
		t.Fatal("expected suppressed while exemption active")
	}

	// Object unchanged, but the exemption has expired: incremental review must
	// reopen the finding and match a full scan.
	after := expiry.Add(time.Minute)
	r2, err := scan.NewEngine(reg, ex, scan.Config{
		StateDir: stateDir, BaselineVer: "1", AsOf: after, Workers: 2,
	}).ReviewIncrementally(snap)
	if err != nil {
		t.Fatal(err)
	}
	if statusOf(r2, "C-001:Pod", "a") != finding.StatusOpen {
		t.Fatal("expected open after exemption expiry on incremental review")
	}
	fullRef, err := scan.NewEngine(reg, ex, scan.Config{
		StateDir: filepath.Join(dir, "ref"), BaselineVer: "1", AsOf: after, Workers: 1,
	}).FullScan(snap)
	if err != nil {
		t.Fatal(err)
	}
	if statusOf(fullRef, "C-001:Pod", "a") != finding.StatusOpen {
		t.Fatal("reference full scan should be open after expiry")
	}
	if findingIDs(r2)[0] != findingIDs(fullRef)[0] {
		t.Fatal("incremental after expiry does not match full scan")
	}
}

func TestBaselineVersionIsolationAndExplicitSwitch(t *testing.T) {
	dir := t.TempDir()
	snapDir := filepath.Join(dir, "snap")
	// Pod missing cpu request and without hostNetwork.
	writeSnapshot(t, snapDir, pod("a", false, ""))
	snap := loadSnap(t, snapDir, 2)
	reg := newReg(t)
	stateDir := filepath.Join(dir, "state")

	r1, err := scan.NewEngine(reg, nil, scan.Config{
		StateDir: stateDir, BaselineVer: "1", AsOf: asOf,
	}).FullScan(snap)
	if err != nil {
		t.Fatal(err)
	}
	// v1: C-003 is medium.
	if sevOf(r1, "C-003:Pod", "a") != finding.SeverityMedium {
		t.Fatalf("v1 C-003 severity = %s want medium", sevOf(r1, "C-003:Pod", "a"))
	}

	// Re-running v1 keeps the identical conclusion even though v2 exists.
	r1b, err := scan.NewEngine(reg, nil, scan.Config{
		StateDir: stateDir, BaselineVer: "1", AsOf: asOf,
	}).ReviewIncrementally(snap)
	if err != nil {
		t.Fatal(err)
	}
	if sevOf(r1b, "C-003:Pod", "a") != finding.SeverityMedium {
		t.Fatal("historical v1 conclusion must not silently change")
	}

	// Explicitly switching to v2 changes the severity and adds isolation.
	r2, err := scan.NewEngine(reg, nil, scan.Config{
		StateDir: stateDir, BaselineVer: "2", AsOf: asOf,
	}).FullScan(snap)
	if err != nil {
		t.Fatal(err)
	}
	if sevOf(r2, "C-003:Pod", "a") != finding.SeverityHigh {
		t.Fatalf("v2 C-003 severity = %s want high", sevOf(r2, "C-003:Pod", "a"))
	}
	// Separate state streams: v1 review still intact.
	r1c, err := scan.NewEngine(reg, nil, scan.Config{
		StateDir: stateDir, BaselineVer: "1", AsOf: asOf,
	}).ReviewIncrementally(snap)
	if err != nil {
		t.Fatal(err)
	}
	if sevOf(r1c, "C-003:Pod", "a") != finding.SeverityMedium {
		t.Fatal("v1 review stream must remain independent of v2")
	}
}

func statusOf(r *scan.Result, check, name string) finding.Status {
	for _, f := range r.Findings {
		if f.CheckID == check && f.Name == name {
			return f.Status
		}
	}
	return "<missing>"
}

func sevOf(r *scan.Result, check, name string) finding.Severity {
	for _, f := range r.Findings {
		if f.CheckID == check && f.Name == name {
			return f.Severity
		}
	}
	return "<missing>"
}
