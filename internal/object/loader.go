package object

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Loader reads cluster objects from a local snapshot directory.
type Loader struct {
	root        string
	concurrency int
}

// NewLoader creates a Loader rooted at dir. concurrency controls parse
// parallelism; the normalized result is identical for any concurrency value
// (including 1 or 0, which means 1).
func NewLoader(dir string, concurrency int) *Loader {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Loader{root: dir, concurrency: concurrency}
}

// rawObject is one decoded snapshot entry before normalization.
type rawObject struct {
	source string
	data   map[string]any
}

// Load walks the snapshot directory, parses every supported file and
// normalizes duplicate copies with a deterministic merge rule:
//
//  1. Among copies with the same Key, the one with the highest
//     metadata.resourceVersion (uint64) wins.
//  2. Ties are broken by the lexicographically smallest source path.
//
// Every leaf-level field disagreement between copies is recorded as a
// Conflict on the MergeReport. The final Snapshot depends only on file
// contents, never on read order or parse concurrency.
func (l *Loader) Load() (*Snapshot, error) {
	var files []string
	err := filepath.WalkDir(l.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".json" || ext == ".jsonl" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk snapshot %q: %w", l.root, err)
	}
	sort.Strings(files)

	// Parse files in parallel. Each file is parsed into an ordered slice of
	// entries; results are collected back in the sorted file order, and merged
	// in a later sequential pass, so scheduling cannot affect the output.
	parsed := make([][]rawObject, len(files))
	errs := make([]error, len(files))
	sem := make(chan struct{}, l.concurrency)
	var wg sync.WaitGroup
	for i, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, f string) {
			defer wg.Done()
			defer func() { <-sem }()
			entries, err := parseFile(f)
			if err != nil {
				errs[i] = err
				return
			}
			parsed[i] = entries
		}(i, f)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	byKey := map[Key][]rawObject{}
	var keyOrder []Key
	seen := map[Key]bool{}
	for _, entries := range parsed {
		for _, ro := range entries {
			obj, err := normalize(ro.source, ro.data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", ro.source, err)
			}
			k := obj.Key
			if !seen[k] {
				seen[k] = true
				keyOrder = append(keyOrder, k)
			}
			byKey[k] = append(byKey[k], rawObject{source: ro.source, data: ro.data})
		}
	}

	snap := &Snapshot{Objects: map[Key]*Object{}}
	for _, k := range keyOrder {
		copies := byKey[k]
		winnerIdx := pickWinner(copies)
		winner, err := normalize(copies[winnerIdx].source, copies[winnerIdx].data)
		if err != nil {
			return nil, err
		}
		snap.Objects[k] = winner

		if len(copies) > 1 {
			snap.Merges = append(snap.Merges, buildMergeReport(k, copies, winnerIdx))
		}
	}
	sortKeys(keyOrder)
	sort.Slice(snap.Merges, func(i, j int) bool {
		a, b := snap.Merges[i].Key, snap.Merges[j].Key
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return snap, nil
}

// parseFile decodes one snapshot file. .json files may hold a single object
// or an array; .jsonl files hold one object per line (blank lines allowed).
func parseFile(path string) ([]rawObject, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var docs []map[string]any
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl":
		docs, err = decodeJSONL(data)
	case ".json":
		docs, err = decodeJSON(data)
	}
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]rawObject, 0, len(docs))
	for _, d := range docs {
		out = append(out, rawObject{source: path, data: d})
	}
	return out, nil
}

// decodeJSON uses UseNumber so numeric fields (including resourceVersion) keep
// an exact textual representation instead of lossy floats.
func decodeJSON(data []byte) ([]map[string]any, error) {
	dec := newDecoder(data)
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}, nil
	case []any:
		out := make([]map[string]any, 0, len(t))
		for i, item := range t {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("array element %d is not an object", i)
			}
			out = append(out, m)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("top-level JSON must be object or array")
	}
}

func decodeJSONL(data []byte) ([]map[string]any, error) {
	var out []map[string]any
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		dec := newDecoder([]byte(trim))
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// normalize converts a decoded document into an Object.
func normalize(source string, d map[string]any) (*Object, error) {
	kind, _ := d["kind"].(string)
	if kind == "" {
		return nil, fmt.Errorf("missing kind")
	}
	meta, _ := d["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	if name == "" {
		return nil, fmt.Errorf("missing metadata.name")
	}
	ns, _ := meta["namespace"].(string)
	labels := map[string]string{}
	if rawLabels, ok := meta["labels"].(map[string]any); ok {
		for k, v := range rawLabels {
			labels[k] = fmt.Sprint(v)
		}
	}
	spec, _ := d["spec"].(map[string]any)
	return &Object{
		Key:      Key{Kind: Kind(kind), Namespace: ns, Name: name},
		Labels:   labels,
		Spec:     spec,
		Metadata: meta,
		Source:   source,
	}, nil
}

// pickWinner implements the deterministic duplicate selection rule.
func pickWinner(copies []rawObject) int {
	winner := 0
	for i := 1; i < len(copies); i++ {
		if outranks(copies[i], copies[winner]) {
			winner = i
		}
	}
	return winner
}

// outranks reports whether a beats b: higher resourceVersion wins; an equal
// revision is broken by the smaller source path.
func outranks(a, b rawObject) bool {
	ra, rb := revisionOf(a.data), revisionOf(b.data)
	if ra != rb {
		return ra > rb
	}
	return a.source < b.source
}

func revisionOf(d map[string]any) uint64 {
	meta, ok := d["metadata"].(map[string]any)
	if !ok {
		return 0
	}
	switch v := meta["resourceVersion"].(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return uint64(n)
		}
	case string:
		var n uint64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	case float64:
		return uint64(v)
	}
	return 0
}

// buildMergeReport records the winner, every contributing source and every
// leaf-level conflict for one duplicated key.
func buildMergeReport(k Key, copies []rawObject, winnerIdx int) MergeReport {
	report := MergeReport{Key: k, Winner: copies[winnerIdx].source}

	// Source copies sorted by source path for stable output.
	idxBySource := make([]int, len(copies))
	for i := range copies {
		idxBySource[i] = i
	}
	sort.Slice(idxBySource, func(a, b int) bool { return copies[idxBySource[a]].source < copies[idxBySource[b]].source })
	for _, i := range idxBySource {
		report.Sources = append(report.Sources, SourceCopy{
			Source:    copies[i].source,
			Revision:  revisionString(copies[i].data),
			ContentID: contentID(copies[i].data),
		})
	}

	// Flatten every copy; a path is conflicting when its rendered value is not
	// identical across all copies. resourceVersion is excluded because its
	// difference is expected and handled by the winner rule.
	flat := make([]map[string]string, len(copies))
	for i, c := range copies {
		flat[i] = flatten(c.data)
	}
	pathSet := map[string]bool{}
	for _, f := range flat {
		for p := range f {
			pathSet[p] = true
		}
	}
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		if p == "metadata.resourceVersion" {
			continue
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		values := map[string]string{}
		distinct := map[string]bool{}
		for i, f := range flat {
			v, present := f[p]
			if !present {
				continue
			}
			values[copies[i].source] = v
			distinct[v] = true
		}
		if len(distinct) > 1 {
			report.Conflicts = append(report.Conflicts, Conflict{
				Field:    p,
				Values:   values,
				Resolved: flat[winnerIdx][p],
			})
		}
	}
	return report
}

func revisionString(d map[string]any) string {
	meta, ok := d["metadata"].(map[string]any)
	if !ok {
		return ""
	}
	switch v := meta["resourceVersion"].(type) {
	case json.Number:
		return v.String()
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// contentID hashes a raw document after key-sorting, independent of formatting.
func contentID(d map[string]any) string {
	return fmt.Sprintf("%x", sha256Sum(canonicalJSON(d)))
}

// flatten renders every leaf of d as path -> canonical-json value.
func flatten(d map[string]any) map[string]string {
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, t[k])
			}
		default:
			out[prefix] = string(canonicalJSON(v))
		}
	}
	walk("", d)
	return out
}
