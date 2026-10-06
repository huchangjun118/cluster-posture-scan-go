package baseline

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Registry holds published baselines. Once published a baseline never changes;
// historical findings stay interpretable even after newer versions exist.
type Registry struct {
	mu       sync.RWMutex
	versions map[Version]*Baseline
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{versions: map[Version]*Baseline{}}
}

// Register publishes an immutable baseline. Registering the same version twice
// with different content is rejected; an identical re-register is a no-op.
func (r *Registry) Register(b *Baseline) error {
	if b == nil || b.Version == "" {
		return fmt.Errorf("baseline must have a version")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.versions[b.Version]; ok {
		if baselineEqual(existing, b) {
			return nil
		}
		return fmt.Errorf("baseline version %q already published with different content; published baselines are immutable", b.Version)
	}
	cp := &Baseline{Version: b.Version, Checks: append([]*Check(nil), b.Checks...)}
	sort.Slice(cp.Checks, func(i, j int) bool { return cp.Checks[i].ID < cp.Checks[j].ID })
	r.versions[b.Version] = cp
	return nil
}

// Get returns the baseline for v.
func (r *Registry) Get(v Version) (*Baseline, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.versions[v]
	if !ok {
		return nil, fmt.Errorf("baseline version %q not found", v)
	}
	return b, nil
}

// Versions returns all registered versions in semantic (newest-last) order.
func (r *Registry) Versions() []Version {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Version, 0, len(r.versions))
	for v := range r.versions {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return versionLess(out[i], out[j]) })
	return out
}

// Latest returns the newest registered version.
func (r *Registry) Latest() (Version, error) {
	vs := r.Versions()
	if len(vs) == 0 {
		return "", fmt.Errorf("no baselines registered")
	}
	return vs[len(vs)-1], nil
}

// versionLess orders dotted numeric versions (e.g. 1.2 < 1.10); non-numeric
// segments fall back to lexicographic order.
func versionLess(a, b Version) bool {
	pa := splitVersion(string(a))
	pb := splitVersion(string(b))
	n := len(pa)
	if len(pb) < n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		if pa[i] == pb[i] {
			continue
		}
		ai, aerr := atoiOK(pa[i])
		bi, berr := atoiOK(pb[i])
		if aerr == nil && berr == nil {
			return ai < bi
		}
		return pa[i] < pb[i]
	}
	return len(pa) < len(pb)
}

func baselineEqual(a, b *Baseline) bool {
	if a.Version != b.Version || len(a.Checks) != len(b.Checks) {
		return false
	}
	// Compare after sorting a copy of IDs; checks are content addressed by
	// their canonical JSON-ish identity.
	ids := map[string]bool{}
	for _, c := range a.Checks {
		ids[c.ID] = true
	}
	for _, c := range b.Checks {
		if !ids[c.ID] {
			return false
		}
	}
	// Same ID set at equal length: compare definitions pairwise in sorted order.
	ac := append([]*Check(nil), a.Checks...)
	bc := append([]*Check(nil), b.Checks...)
	sort.Slice(ac, func(i, j int) bool { return ac[i].ID < ac[j].ID })
	sort.Slice(bc, func(i, j int) bool { return bc[i].ID < bc[j].ID })
	for i := range ac {
		if checkDigest(ac[i]) != checkDigest(bc[i]) {
			return false
		}
	}
	return true
}

func splitVersion(v string) []string {
	return strings.Split(v, ".")
}

func atoiOK(s string) (int, error) { return strconv.Atoi(s) }
