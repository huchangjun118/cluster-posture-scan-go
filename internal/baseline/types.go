package baseline

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
)

// Version is an immutable baseline version identifier.
type Version string

// Operator enumerates the supported field predicates. Every operator evaluates
// one field against one expected value; checks combine predicates with AND.
type Operator string

const (
	OpEq            Operator = "eq"            // field present and value equals expected
	OpNe            Operator = "ne"            // field present and value differs from expected
	OpExists        Operator = "exists"        // field present
	OpMissing       Operator = "missing"       // field absent
	OpLt            Operator = "lt"            // numeric field < expected
	OpLte           Operator = "lte"           // numeric field <= expected
	OpGt            Operator = "gt"            // numeric field > expected
	OpGte           Operator = "gte"           // numeric field >= expected
	OpMatches       Operator = "matches"       // string field matches expected regexp
	OpAllContainers Operator = "allContainers" // resource pseudo-operator, see evaluate
)

// FieldSelector locates a field within an object.
//
// Supported roots:
//   - "labels.<key>"
//   - "metadata.<key>"
//   - "spec.<dotted.path>"
//   - "resource:<requests|limits>.<cpu|memory>[.<container-name>]"
//     evaluates against every (init) container of a workload; a missing
//     container contributes the empty value.
type FieldSelector struct {
	Path string
}

// Condition evaluates one field predicate against an object.
type Condition struct {
	Field FieldSelector `json:"field"`
	Op    Operator      `json:"op"`
	Value string        `json:"value"`
}

// Check declares one baseline rule. A check applies to exactly one object kind.
// The object is non-compliant when every Condition holds (AND semantics); the
// rendered Message describes the violation.
type Check struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Kind        object.Kind      `json:"kind"`
	Severity    finding.Severity `json:"severity"`
	Conditions  []Condition      `json:"conditions"`
	Description string           `json:"description"`
	Message     string           `json:"message"`
}

// Baseline is one published, immutable set of checks.
type Baseline struct {
	Version Version  `json:"version"`
	Checks  []*Check `json:"checks"`
}

// ChecksForKind returns checks applicable to k, sorted by ID.
func (b *Baseline) ChecksForKind(k object.Kind) []*Check {
	var out []*Check
	for _, c := range b.Checks {
		if c.Kind == k {
			out = append(out, c)
		}
	}
	return out
}

// Evaluate runs the check against one object. It reports whether the object is
// non-compliant and a deterministic, human-readable message.
func (c *Check) Evaluate(o *object.Object) (bool, string) {
	details := map[string][]string{}
	for _, cond := range c.Conditions {
		ok, bad := cond.holds(o)
		if !ok {
			return false, ""
		}
		if len(bad) > 0 {
			details[cond.Field.Path] = bad
		}
	}
	msg := c.Message
	if len(details) > 0 {
		paths := make([]string, 0, len(details))
		for p := range details {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		var parts []string
		for _, p := range paths {
			vals := details[p]
			sort.Strings(vals)
			parts = append(parts, p+": "+strings.Join(vals, ", "))
		}
		msg = msg + " [" + strings.Join(parts, "; ") + "]"
	}
	return true, msg
}

// holds evaluates a condition. bad lists violating members (container names)
// for resource pseudo-fields and is empty for ordinary fields.
func (cond Condition) holds(o *object.Object) (bool, []string) {
	if strings.HasPrefix(cond.Field.Path, "resource:") {
		return cond.holdsResource(o)
	}
	if strings.HasPrefix(cond.Field.Path, "container:") {
		return cond.holdsContainerField(o)
	}
	val, present := lookupField(o, cond.Field.Path)
	switch cond.Op {
	case OpEq:
		return present && val == cond.Value, nil
	case OpNe:
		return present && val != cond.Value, nil
	case OpExists:
		return present, nil
	case OpMissing:
		return !present, nil
	case OpMatches:
		re, err := regexp.Compile(cond.Value)
		if err != nil {
			return false, nil
		}
		return present && re.MatchString(val), nil
	case OpLt, OpLte, OpGt, OpGte:
		if !present {
			return false, nil
		}
		got, err1 := strconv.ParseFloat(val, 64)
		want, err2 := strconv.ParseFloat(cond.Value, 64)
		if err1 != nil || err2 != nil {
			return false, nil
		}
		switch cond.Op {
		case OpLt:
			return got < want, nil
		case OpLte:
			return got <= want, nil
		case OpGt:
			return got > want, nil
		case OpGte:
			return got >= want, nil
		}
	}
	return false, nil
}

// holdsContainerField evaluates "container:<dotted.path>" against every
// (init) container. The condition holds when at least one container satisfies
// it; offending container names are returned for the message.
func (cond Condition) holdsContainerField(o *object.Object) (bool, []string) {
	rel := strings.TrimPrefix(cond.Field.Path, "container:")
	var bad []string
	found := false
	for _, ctr := range o.Containers() {
		if v, ok := lookupNested(ctr.Raw, strings.Split(rel, ".")); containerOne(cond, v, ok) {
			bad = append(bad, ctr.Name)
			found = true
		}
	}
	return found, bad
}

func containerOne(cond Condition, val string, present bool) bool {
	switch cond.Op {
	case OpEq:
		return present && val == cond.Value
	case OpNe:
		return present && val != cond.Value
	case OpExists:
		return present
	case OpMissing:
		return !present
	}
	return false
}

// holdsResource implements resource: conditions across containers. Semantics
// mirror holdsContainerField: the condition holds (the object is non-compliant)
// when at least one in-scope container satisfies the predicate; those container
// names are returned for the message.
func (cond Condition) holdsResource(o *object.Object) (bool, []string) {
	wantType, wantName, fixedContainer, err := parseResourcePath(cond.Field.Path)
	if err != nil {
		return false, nil
	}
	containers := o.Containers()
	var matched []string
	checked := 0
	for _, ctr := range containers {
		if fixedContainer != "" && ctr.Name != fixedContainer {
			continue
		}
		checked++
		val, present := containerResource(ctr, wantType, wantName)
		if resourceOne(cond, val, present) {
			matched = append(matched, ctr.Name)
		}
	}
	if fixedContainer != "" && checked == 0 {
		return false, nil
	}
	return len(matched) > 0, matched
}

// resourceOne evaluates a single container value.
func resourceOne(cond Condition, val string, present bool) bool {
	switch cond.Op {
	case OpEq:
		return present && val == cond.Value
	case OpNe:
		return present && val != cond.Value
	case OpExists:
		return present
	case OpMissing:
		return !present
	case OpLt, OpLte, OpGt, OpGte:
		if !present {
			return false
		}
		got, err := resourceNumber(val)
		if err != nil {
			return false
		}
		want, err := strconv.ParseFloat(cond.Value, 64)
		if err != nil {
			return false
		}
		switch cond.Op {
		case OpLt:
			return got < want
		case OpLte:
			return got <= want
		case OpGt:
			return got > want
		case OpGte:
			return got >= want
		}
	}
	return false
}

// lookupField resolves labels./metadata./spec. paths to a leaf string.
func lookupField(o *object.Object, path string) (string, bool) {
	switch {
	case strings.HasPrefix(path, "labels."):
		v, ok := o.Labels[strings.TrimPrefix(path, "labels.")]
		return v, ok
	case strings.HasPrefix(path, "metadata."):
		v, ok := lookupNested(o.Metadata, strings.Split(strings.TrimPrefix(path, "metadata."), "."))
		return v, ok
	case strings.HasPrefix(path, "spec."):
		return lookupNested(o.Spec, strings.Split(strings.TrimPrefix(path, "spec."), "."))
	default:
		return "", false
	}
}

func lookupNested(root map[string]any, parts []string) (string, bool) {
	if root == nil {
		return "", false
	}
	var cur any = root
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = m[p]
		if !ok {
			return "", false
		}
	}
	return leafString(cur)
}

func leafString(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case int:
		return strconv.Itoa(t), true
	default:
		return fmt.Sprint(t), true
	}
}

func parseResourcePath(path string) (resType, resName, container string, err error) {
	body := strings.TrimPrefix(path, "resource:")
	parts := strings.Split(body, ".")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("bad resource path %q", path)
	}
	resType, resName = parts[0], parts[1]
	if resType != "requests" && resType != "limits" {
		return "", "", "", fmt.Errorf("bad resource type %q", resType)
	}
	if len(parts) == 3 {
		container = parts[2]
	}
	return resType, resName, container, nil
}

func containerResource(c object.Container, resType, resName string) (string, bool) {
	section, ok := c.Resources[resType].(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := section[resName]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// resourceNumber parses Kubernetes-style quantities used in checks.
// Supports plain numbers and milli/mega CPU/memory suffixes relevant to
// comparisons: m (1e-3), n/u, k/K, M/G (binary memory handled as needed).
func resourceNumber(s string) (float64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty quantity")
	}
	// Pure number.
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return n, nil
	}
	multipliers := map[string]float64{
		"m":  0.001,
		"n":  1e-9,
		"u":  1e-6,
		"k":  1e3,
		"K":  1e3,
		"M":  1e6,
		"G":  1e9,
		"Ki": 1024,
		"Mi": 1024 * 1024,
		"Gi": 1024 * 1024 * 1024,
	}
	// Longest suffix first (Ki vs K).
	suffixes := []string{"Ki", "Mi", "Gi", "m", "n", "u", "k", "K", "M", "G"}
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			num := strings.TrimSuffix(s, suf)
			n, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, err
			}
			return n * multipliers[suf], nil
		}
	}
	return 0, fmt.Errorf("unparseable quantity %q", s)
}
