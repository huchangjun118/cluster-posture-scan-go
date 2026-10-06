package object

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Kind identifies a class of cluster objects.
type Kind string

// Well-known object kinds understood by the scanner.
const (
	KindPod            Kind = "Pod"
	KindDeployment     Kind = "Deployment"
	KindStatefulSet    Kind = "StatefulSet"
	KindDaemonSet      Kind = "DaemonSet"
	KindJob            Kind = "Job"
	KindCronJob        Kind = "CronJob"
	KindService        Kind = "Service"
	KindNamespace      Kind = "Namespace"
	KindServiceAccount Kind = "ServiceAccount"
)

// Key uniquely identifies an object within a snapshot: its kind and namespaced name.
type Key struct {
	Kind      Kind   `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// String renders the key for reports.
func (k Key) String() string {
	if k.Namespace == "" {
		return string(k.Kind) + "/" + k.Name
	}
	return string(k.Kind) + "/" + k.Namespace + "/" + k.Name
}

// Object is a single normalized cluster object loaded from a snapshot.
type Object struct {
	Key      Key
	Labels   map[string]string
	Spec     map[string]any
	Metadata map[string]any
	Source   string // snapshot file the winning copy came from
}

// Container describes one (init) container.
type Container struct {
	Name      string
	Init      bool
	Resources map[string]any
	Raw       map[string]any
}

// asMap pulls a nested map out of an untyped decoded structure.
func asMap(m map[string]any, path ...string) map[string]any {
	cur := m
	for _, p := range path {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// Containers returns the workload containers (regular and init) for the object,
// following the standard pod-template locations of each supported kind.
func (o *Object) Containers() []Container {
	var podSpec map[string]any
	switch o.Key.Kind {
	case KindPod:
		podSpec = o.Spec
	case KindDeployment, KindStatefulSet, KindDaemonSet, KindJob:
		podSpec = asMap(o.Spec, "template", "spec")
	case KindCronJob:
		podSpec = asMap(o.Spec, "jobTemplate", "spec", "template", "spec")
	default:
		return nil
	}
	if podSpec == nil {
		return nil
	}
	var out []Container
	collect := func(key string, init bool) {
		arr, ok := podSpec[key].([]any)
		if !ok {
			return
		}
		for _, item := range arr {
			c, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := c["name"].(string)
			res, _ := c["resources"].(map[string]any)
			out = append(out, Container{Name: name, Init: init, Resources: res, Raw: c})
		}
	}
	collect("initContainers", true)
	collect("containers", false)
	return out
}

// MergeReport records how duplicate/conflicting copies of an object were normalized.
type MergeReport struct {
	Key       Key          `json:"key"`
	Winner    string       `json:"winner"`
	Sources   []SourceCopy `json:"sources"`
	Conflicts []Conflict   `json:"conflicts"`
}

// SourceCopy is one raw copy of an object seen while loading.
type SourceCopy struct {
	Source    string `json:"source"`
	Revision  string `json:"revision"`
	ContentID string `json:"content_id"`
}

// Conflict describes a field disagreement between duplicate copies.
type Conflict struct {
	Field    string            `json:"field"`
	Values   map[string]string `json:"values"`
	Resolved string            `json:"resolved"`
}

// Snapshot is the normalized, deterministic result of loading a local directory.
type Snapshot struct {
	Objects map[Key]*Object
	Merges  []MergeReport // sorted by Key
}

// Keys returns all object keys in deterministic (kind, namespace, name) order.
func (s *Snapshot) Keys() []Key {
	keys := make([]Key, 0, len(s.Objects))
	for k := range s.Objects {
		keys = append(keys, k)
	}
	sortKeys(keys)
	return keys
}

// Get returns the object for a key, or nil.
func (s *Snapshot) Get(k Key) *Object { return s.Objects[k] }

func sortKeys(keys []Key) {
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
}

// canonicalContent is the semantic content used for fingerprints and conflict
// diffs. resourceVersion is deliberately excluded: it is copy metadata, not
// object state.
func (o *Object) canonicalContent() map[string]any {
	meta := map[string]any{}
	for k, v := range o.Metadata {
		if k == "resourceVersion" {
			continue
		}
		meta[k] = v
	}
	return map[string]any{
		"kind":      string(o.Key.Kind),
		"namespace": o.Key.Namespace,
		"name":      o.Key.Name,
		"labels":    o.Labels,
		"spec":      o.Spec,
		"metadata":  meta,
	}
}

// canonicalJSON renders v with sorted object keys so equal content always
// serializes identically.
func canonicalJSON(v any) []byte {
	b, err := json.Marshal(sortValue(v))
	if err != nil {
		// All values here originate from JSON decoding or string-keyed maps.
		panic(err)
	}
	return b
}

func sortValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(t))
		for _, k := range keys {
			out[k] = sortValue(t[k])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = sortValue(t[i])
		}
		return out
	default:
		return v
	}
}

// Fingerprint is a stable content hash of the object, independent of file
// source, read order or resourceVersion.
func (o *Object) Fingerprint() string {
	sum := sha256.Sum256(canonicalJSON(o.canonicalContent()))
	return hex.EncodeToString(sum[:])
}

// ID is a stable identity of the whole snapshot: the hash of all
// (key, object-fingerprint) pairs, independent of read order/concurrency.
func (s *Snapshot) ID() string {
	keys := s.Keys()
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k.String()))
		h.Write([]byte{0})
		h.Write([]byte(s.Objects[k].Fingerprint()))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
