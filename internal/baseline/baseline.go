// Package baseline 定义版本化检查基线并对单对象求值。
//
// 基线文件可包含多个版本；结论中始终记录求值所用的版本号，
// 只有显式选择另一个版本才会改变结论，历史结论因此始终可解释。
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

// Condition 描述对对象某字段的判定条件。
type Condition struct {
	// Path 为点分字段路径，如 "spec.privileged"。
	Path string `json:"path" yaml:"path"`
	// Op 为判定操作：eq ne exists not-exists in contains regex lt lte gt gte。
	Op string `json:"op" yaml:"op"`
	// Value 为比较右值（exists/not-exists 不需要）。
	Value any `json:"value,omitempty" yaml:"value,omitempty"`
}

// Check 是一条基线检查。
type Check struct {
	ID        string         `json:"id" yaml:"id"`
	Severity  model.Severity `json:"severity" yaml:"severity"`
	Kinds     []string       `json:"kinds" yaml:"kinds"`
	Condition Condition      `json:"condition" yaml:"condition"`
	Message   string         `json:"message" yaml:"message"`
}

// Baseline 是带版本的检查集合。
type Baseline struct {
	Version string  `json:"version" yaml:"version"`
	Checks  []Check `json:"checks" yaml:"checks"`
}

// file 是基线文件的顶层结构，支持多版本共存。
type file struct {
	Versions []Baseline `json:"versions" yaml:"versions"`
}

// LoadFile 从文件加载指定版本的基线；version 为空时取文件中第一个版本。
func LoadFile(path, version string) (*Baseline, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var f file
	if err := yaml.Unmarshal(content, &f); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if len(f.Versions) == 0 {
		return nil, fmt.Errorf("baseline %s: no versions defined", path)
	}
	if version == "" {
		bl := f.Versions[0]
		return &bl, bl.validate()
	}
	for i := range f.Versions {
		if f.Versions[i].Version == version {
			bl := f.Versions[i]
			return &bl, bl.validate()
		}
	}
	var avail []string
	for _, v := range f.Versions {
		avail = append(avail, v.Version)
	}
	sort.Strings(avail)
	return nil, fmt.Errorf("baseline version %q not found (available: %s)", version, strings.Join(avail, ", "))
}

// validate 校验基线定义合法性。
func (b *Baseline) validate() error {
	if b.Version == "" {
		return fmt.Errorf("baseline version must not be empty")
	}
	seen := map[string]bool{}
	for _, c := range b.Checks {
		if c.ID == "" {
			return fmt.Errorf("check with empty id")
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate check id %q", c.ID)
		}
		seen[c.ID] = true
		if len(c.Kinds) == 0 {
			return fmt.Errorf("check %q: kinds must not be empty", c.ID)
		}
		switch c.Severity {
		case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow:
		default:
			return fmt.Errorf("check %q: invalid severity %q", c.ID, c.Severity)
		}
		if _, err := compileOp(c.Condition); err != nil {
			return fmt.Errorf("check %q: %w", c.ID, err)
		}
	}
	return nil
}

// AppliesTo 判断检查是否适用于某对象种类。
func (c Check) AppliesTo(kind string) bool {
	for _, k := range c.Kinds {
		if k == kind || k == "*" {
			return true
		}
	}
	return false
}

// Eval 对单个对象执行单条检查，返回是否通过。
// 条件成立视为违规（fail），不成立视为通过（pass）。
func Eval(c Check, obj model.Object) (bool, error) {
	fn, err := compileOp(c.Condition)
	if err != nil {
		return false, err
	}
	actual, found := lookup(obj.Fields, c.Condition.Path)
	violated, err := fn(actual, found)
	if err != nil {
		return false, fmt.Errorf("check %q on %s: %w", c.ID, obj.Ref.Key(), err)
	}
	return !violated, nil
}

// lookup 按点分路径取值。
func lookup(fields map[string]any, path string) (any, bool) {
	var cur any = fields
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

type opFunc func(actual any, found bool) (bool, error)

// compileOp 把条件编译为求值函数；返回的 violated=true 表示命中违规。
func compileOp(cond Condition) (opFunc, error) {
	switch cond.Op {
	case "exists":
		return func(_ any, found bool) (bool, error) { return found, nil }, nil
	case "not-exists":
		return func(_ any, found bool) (bool, error) { return !found, nil }, nil
	case "eq":
		return func(actual any, found bool) (bool, error) {
			return found && valuesEqual(actual, cond.Value), nil
		}, nil
	case "ne":
		// 缺失视为不满足"必须等于"的要求，同样命中违规。
		return func(actual any, found bool) (bool, error) {
			return !found || !valuesEqual(actual, cond.Value), nil
		}, nil
	case "in":
		list, ok := cond.Value.([]any)
		if !ok {
			return nil, fmt.Errorf("op in requires a list value")
		}
		return func(actual any, found bool) (bool, error) {
			if !found {
				return false, nil
			}
			for _, v := range list {
				if valuesEqual(actual, v) {
					return true, nil
				}
			}
			return false, nil
		}, nil
	case "contains":
		return func(actual any, found bool) (bool, error) {
			if !found {
				return false, nil
			}
			switch a := actual.(type) {
			case []any:
				for _, v := range a {
					if valuesEqual(v, cond.Value) {
						return true, nil
					}
				}
			case string:
				s, ok := cond.Value.(string)
				if !ok {
					return false, fmt.Errorf("op contains on string requires string value")
				}
				return strings.Contains(a, s), nil
			default:
				return false, fmt.Errorf("op contains unsupported on %T", actual)
			}
			return false, nil
		}, nil
	case "regex":
		pat, ok := cond.Value.(string)
		if !ok {
			return nil, fmt.Errorf("op regex requires a string value")
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		return func(actual any, found bool) (bool, error) {
			s, ok := actual.(string)
			return found && ok && re.MatchString(s), nil
		}, nil
	case "lt", "lte", "gt", "gte":
		threshold, ok := toFloat(cond.Value)
		if !ok {
			return nil, fmt.Errorf("op %s requires a numeric value", cond.Op)
		}
		return func(actual any, found bool) (bool, error) {
			if !found {
				return false, nil
			}
			f, ok := toFloat(actual)
			if !ok {
				return false, fmt.Errorf("op %s on non-numeric field", cond.Op)
			}
			switch cond.Op {
			case "lt":
				return f < threshold, nil
			case "lte":
				return f <= threshold, nil
			case "gt":
				return f > threshold, nil
			default:
				return f >= threshold, nil
			}
		}, nil
	default:
		return nil, fmt.Errorf("unknown op %q", cond.Op)
	}
}

// valuesEqual 以规范化数值语义比较两个值。
func valuesEqual(a, b any) bool {
	if fa, ok := toFloat(a); ok {
		if fb, ok := toFloat(b); ok {
			return fa == fb
		}
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	default:
		return 0, false
	}
}
