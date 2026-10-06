// Package snapshot 从本地目录读入集群对象快照并归一。
//
// 合并规则（明确定义且可复现）：
//   - 对象以 (Kind, Namespace, Name) 为唯一键；
//   - 同一键出现多份文档时，按 (文件相对路径, 文件内文档序号) 字典序排序，
//     字典序最小者优先级最高；
//   - 字段级深合并：map 递归合并，标量冲突时高优先级文档的值胜出，
//     低优先级文档仅补充高优先级文档中缺失的键；
//   - 解析可并发进行，但合并只在排序后的序列上做，因此与读入顺序、
//     并发度无关，结果逐条一致。
package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

// rawDoc 是一份尚未归一的文档。
type rawDoc struct {
	path  string // 相对路径
	index int    // 文件内文档序号
	data  map[string]any
}

// Load 读取目录下所有快照文件，返回归一后的对象集合（按对象键排序）。
func Load(dir string) ([]model.Object, error) {
	return LoadWithConcurrency(dir, runtime.NumCPU())
}

// LoadWithConcurrency 与 Load 相同，但显式指定解析并发度（用于测试顺序无关性）。
func LoadWithConcurrency(dir string, concurrency int) ([]model.Object, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk snapshot dir: %w", err)
	}
	sort.Strings(files)

	// 并发解析文件；解析结果只与文件内容有关，与调度顺序无关。
	docs := make([][]rawDoc, len(files))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var firstErr error
	for i, f := range files {
		wg.Add(1)
		go func(i int, f string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rel, err := filepath.Rel(dir, f)
			if err != nil {
				rel = f
			}
			parsed, err := parseFile(rel, f)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			docs[i] = parsed
		}(i, f)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	var all []rawDoc
	for _, d := range docs {
		all = append(all, d...)
	}
	// 全局按 (路径, 序号) 排序，保证合并输入与读入顺序无关。
	sort.Slice(all, func(i, j int) bool {
		if all[i].path != all[j].path {
			return all[i].path < all[j].path
		}
		return all[i].index < all[j].index
	})

	merged := map[string]model.Object{}
	var order []string
	for _, d := range all {
		obj, err := toObject(d)
		if err != nil {
			return nil, err
		}
		key := obj.Ref.Key()
		if prev, ok := merged[key]; ok {
			// prev 来自字典序更小的文档，优先级更高。
			obj = model.Object{
				Ref:    prev.Ref,
				Fields: mergeFields(prev.Fields, obj.Fields),
				Source: prev.Source,
			}
		} else {
			order = append(order, key)
		}
		merged[key] = obj
	}
	sort.Strings(order)
	out := make([]model.Object, 0, len(order))
	for _, k := range order {
		out = append(out, merged[k])
	}
	return out, nil
}

// parseFile 解析单个文件为若干文档。支持多文档 YAML 与 JSON（对象或数组）。
func parseFile(rel, abs string) ([]rawDoc, error) {
	content, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	if strings.ToLower(filepath.Ext(abs)) == ".json" {
		return parseJSONDocs(rel, content)
	}
	var docs []rawDoc
	dec := yaml.NewDecoder(bytes.NewReader(content))
	idx := 0
	for {
		var data map[string]any
		err := dec.Decode(&data)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("parse %s doc %d: %w", rel, idx, err)
		}
		if data == nil {
			idx++
			continue
		}
		docs = append(docs, rawDoc{path: rel, index: idx, data: normalize(data).(map[string]any)})
		idx++
	}
	return docs, nil
}

func parseJSONDocs(rel string, content []byte) ([]rawDoc, error) {
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return nil, nil
	}
	if content[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(content, &arr); err != nil {
			return nil, fmt.Errorf("parse %s: %w", rel, err)
		}
		docs := make([]rawDoc, 0, len(arr))
		for i, d := range arr {
			docs = append(docs, rawDoc{path: rel, index: i, data: normalize(d).(map[string]any)})
		}
		return docs, nil
	}
	var d map[string]any
	if err := json.Unmarshal(content, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", rel, err)
	}
	return []rawDoc{{path: rel, index: 0, data: normalize(d).(map[string]any)}}, nil
}

// normalize 把 yaml 解码出的 map[any]any 等形态规整为 JSON 兼容形态。
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = normalize(val)
		}
		return m
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[fmt.Sprint(k)] = normalize(val)
		}
		return m
	case []any:
		for i := range t {
			t[i] = normalize(t[i])
		}
		return t
	default:
		return v
	}
}

// toObject 从原始文档提取对象标识并构造 Object。
func toObject(d rawDoc) (model.Object, error) {
	kind, _ := d.data["kind"].(string)
	meta, _ := d.data["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	ns, _ := meta["namespace"].(string)
	if kind == "" || name == "" {
		return model.Object{}, fmt.Errorf("%s doc %d: missing kind or metadata.name", d.path, d.index)
	}
	return model.Object{
		Ref:    model.ObjectRef{Kind: kind, Namespace: ns, Name: name},
		Fields: d.data,
		Source: d.path,
	}, nil
}

// mergeFields 深合并两个字段集；冲突时 hi 胜出，lo 仅补充缺失键。
func mergeFields(hi, lo map[string]any) map[string]any {
	out := make(map[string]any, len(hi)+len(lo))
	for k, v := range lo {
		out[k] = v
	}
	for k, v := range hi {
		if lv, ok := out[k]; ok {
			hm, hok := v.(map[string]any)
			lm, lok := lv.(map[string]any)
			if hok && lok {
				out[k] = mergeFields(hm, lm)
				continue
			}
		}
		out[k] = v
	}
	return out
}
