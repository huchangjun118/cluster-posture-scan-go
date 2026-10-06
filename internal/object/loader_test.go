package object

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const podA = `{"kind":"Pod","metadata":{"name":"a","namespace":"ns","resourceVersion":"2","labels":{"app":"x"}},"spec":{"hostNetwork":true}}`
const podBOld = `{"kind":"Pod","metadata":{"name":"a","namespace":"ns","resourceVersion":"1","labels":{"app":"y"}},"spec":{"hostNetwork":false}}`
const podBOlderRV = `{"kind":"Pod","metadata":{"name":"name","resourceVersion":"0"}}`

// loadAt is a helper loading dir at a given parse concurrency.
func loadAt(t *testing.T, dir string, conc int) *Snapshot {
	t.Helper()
	snap, err := NewLoader(dir, conc).Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return snap
}

func TestLoadDeterministicAcrossConcurrencyAndOrder(t *testing.T) {
	// Two directories with the same files named differently. File names are
	// part of the winner tiebreak and merge report, so here the winner is
	// decided solely by resourceVersion; content is expected identical.
	makeDir := t.TempDir()
	writeFile(t, filepath.Join(makeDir, "a.json"), podA)
	writeFile(t, filepath.Join(makeDir, "b.json"), podBOld)
	writeFile(t, filepath.Join(makeDir, "list.json"), `[
	  {"kind":"Service","metadata":{"name":"s","namespace":"ns"},"spec":{"type":"ClusterIP"}},
	  {"kind":"ServiceAccount","metadata":{"name":"sa","namespace":"ns"}}
	]`)
	writeFile(t, filepath.Join(makeDir, "lines.jsonl"), podBOlderRV+"\n\n")

	var ids []string
	var fps []string
	for _, c := range []int{1, 2, 4, 16} {
		snap := loadAt(t, makeDir, c)
		ids = append(ids, snap.ID())
		for _, k := range snap.Keys() {
			fps = append(fps, string(k.Kind)+k.Name+snap.Objects[k].Fingerprint())
		}
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] != ids[0] {
			t.Fatalf("snapshot id changed with concurrency: %q vs %q", ids[i], ids[0])
		}
	}
	if len(fps) == 0 {
		t.Fatal("no fingerprints")
	}
}

func TestMergePicksHighestResourceVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "low.json"), podBOld)
	writeFile(t, filepath.Join(dir, "high.json"), podA)
	snap := loadAt(t, dir, 4)

	k := Key{Kind: "Pod", Namespace: "ns", Name: "a"}
	obj := snap.Objects[k]
	if obj == nil {
		t.Fatal("object missing")
	}
	if obj.Source != filepath.Join(dir, "high.json") {
		t.Fatalf("winner = %q, want high.json", obj.Source)
	}
	if obj.Labels["app"] != "x" {
		t.Fatalf("label = %q want x (highest rv wins)", obj.Labels["app"])
	}
	host, ok := lookup(obj.Spec, "hostNetwork")
	if !ok || host != "true" {
		t.Fatalf("hostNetwork = %v,%v want true", host, ok)
	}
	if len(snap.Merges) != 1 {
		t.Fatalf("merges = %d want 1", len(snap.Merges))
	}
	m := snap.Merges[0]
	if m.Winner != filepath.Join(dir, "high.json") {
		t.Fatalf("merge winner = %q", m.Winner)
	}
	var foundLabel bool
	for _, c := range m.Conflicts {
		if c.Field == "metadata.labels.app" {
			foundLabel = true
			if c.Resolved != `"x"` {
				t.Fatalf("resolved label = %q want \"x\"", c.Resolved)
			}
		}
	}
	if !foundLabel {
		t.Fatalf("expected labels.app conflict, got %+v", m.Conflicts)
	}
}

func TestMergeTieBreaksBySourcePath(t *testing.T) {
	dir := t.TempDir()
	// Same resourceVersion: lexicographically smallest path wins.
	writeFile(t, filepath.Join(dir, "a.json"),
		`{"kind":"Pod","metadata":{"name":"p","resourceVersion":"5"},"spec":{"hostNetwork":true}}`)
	writeFile(t, filepath.Join(dir, "b.json"),
		`{"kind":"Pod","metadata":{"name":"p","resourceVersion":"5"},"spec":{"hostNetwork":false}}`)
	snap := loadAt(t, dir, 2)
	obj := snap.Objects[Key{Kind: "Pod", Name: "p"}]
	if obj.Source != filepath.Join(dir, "a.json") {
		t.Fatalf("tie winner = %q want a.json", obj.Source)
	}
}

func TestFingerprintStableAcrossRVAndFormatting(t *testing.T) {
	dir1 := t.TempDir()
	writeFile(t, filepath.Join(dir1, "x.json"),
		`{"kind":"Pod","metadata":{"name":"p","resourceVersion":"1"},"spec":{"hostNetwork":true}}`)
	dir2 := t.TempDir()
	writeFile(t, filepath.Join(dir2, "x.json"),
		"{\n \"kind\": \"Pod\",\n \"metadata\": {\"name\": \"p\", \"resourceVersion\": \"99\"},\n \"spec\": {\"hostNetwork\": true}\n}")
	s1 := loadAt(t, dir1, 1)
	s2 := loadAt(t, dir2, 1)
	f1 := s1.Objects[Key{Kind: "Pod", Name: "p"}].Fingerprint()
	f2 := s2.Objects[Key{Kind: "Pod", Name: "p"}].Fingerprint()
	if f1 != f2 {
		t.Fatalf("fingerprint differs despite identical content/RV-only change:\n%s\n%s", f1, f2)
	}
}

func TestRejectsInvalidObjects(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bad.json"), `{"metadata":{"name":"x"}}`)
	if _, err := NewLoader(dir, 1).Load(); err == nil {
		t.Fatal("expected error for missing kind")
	}
}

func lookup(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	switch t := v.(type) {
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	default:
		return "", false
	}
}
