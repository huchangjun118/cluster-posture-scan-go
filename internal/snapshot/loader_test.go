package snapshot

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// 不同并发度下解析结果必须逐条一致。
func TestLoadDeterministicAcrossConcurrency(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 30; i++ {
		name := string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".yaml"
		files[name] = "kind: Deployment\nmetadata:\n  name: app-" + string(rune('a'+i)) + "\n  namespace: ns\nspec:\n  replicas: " + string(rune('1'+i%3)) + "\n"
	}
	dir := writeFiles(t, files)
	var want []model.Object
	for _, conc := range []int{1, 2, 4, 16} {
		got, err := LoadWithConcurrency(dir, conc)
		if err != nil {
			t.Fatalf("concurrency %d: %v", conc, err)
		}
		if want == nil {
			want = got
			continue
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("concurrency %d produced different objects", conc)
		}
	}
	if len(want) != 30 {
		t.Fatalf("expected 30 objects, got %d", len(want))
	}
}

// 字段冲突按 (路径, 文档序号) 字典序归一：字典序小者胜出，缺失键被补充。
func TestConflictMergeRule(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a.yaml": "kind: Pod\nmetadata:\n  name: p\n  namespace: ns\nspec:\n  privileged: true\n  image: nginx\n",
		"b.yaml": "kind: Pod\nmetadata:\n  name: p\n  namespace: ns\nspec:\n  privileged: false\n  hostNetwork: true\n",
	})
	objs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 {
		t.Fatalf("expected 1 merged object, got %d", len(objs))
	}
	spec := objs[0].Fields["spec"].(map[string]any)
	if spec["privileged"] != true {
		t.Fatalf("a.yaml should win scalar conflict, got %v", spec["privileged"])
	}
	if spec["hostNetwork"] != true {
		t.Fatalf("missing key should be filled from b.yaml, got %v", spec["hostNetwork"])
	}
	if objs[0].Source != "a.yaml" {
		t.Fatalf("source should be highest-priority file, got %q", objs[0].Source)
	}
}

// 同一文件内多文档：序号小者优先。
func TestMultiDocPriority(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"m.yaml": "kind: Pod\nmetadata:\n  name: p\nspec:\n  x: first\n---\nkind: Pod\nmetadata:\n  name: p\nspec:\n  x: second\n",
	})
	objs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objs))
	}
	if got := objs[0].Fields["spec"].(map[string]any)["x"]; got != "first" {
		t.Fatalf("earlier doc should win, got %v", got)
	}
}

// JSON 数组与 YAML 混合读入。
func TestJSONAndYAML(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a.json": `[{"kind":"Pod","metadata":{"name":"p1"}},{"kind":"Pod","metadata":{"name":"p2"}}]`,
		"b.yaml": "kind: Service\nmetadata:\n  name: s1\n",
	})
	objs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 3 {
		t.Fatalf("expected 3 objects, got %d", len(objs))
	}
	keys := []string{objs[0].Ref.Key(), objs[1].Ref.Key(), objs[2].Ref.Key()}
	want := []string{"Pod//p1", "Pod//p2", "Service//s1"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("objects not sorted by key: %v", keys)
	}
}
