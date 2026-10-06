// Package engine 并发执行检查并产出确定性结论。
//
// 结论只取决于 (对象内容, 基线版本, 生效豁免)，与调度顺序、
// 并发度无关：所有任务并发求值后统一按 (CheckID, 对象键) 排序输出。
// 豁免不作为求值输入，而是求值后的纯函数后处理，因此缓存的
// 增量结论在豁免变化时依然安全可复用。
package engine

import (
	"fmt"
	"runtime"
	"sort"
	"sync"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/exemption"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

// Options 控制扫描行为。
type Options struct {
	// Concurrency 为求值并发度；<=0 时取 NumCPU。
	Concurrency int
	// Exemptions 为当前生效的豁免集合。
	Exemptions []exemption.Exemption
}

// Result 是一次扫描的完整结论。
type Result struct {
	BaselineVersion string          `json:"baselineVersion"`
	Findings        []model.Finding `json:"findings"`
}

// EvalObject 对单个对象执行基线中全部适用检查，返回原始结论
// （pass/fail，不套用豁免），按 CheckID 排序。结果是对象内容与
// 基线版本的纯函数，可安全缓存用于增量复核与断点恢复。
func EvalObject(bl *baseline.Baseline, obj model.Object) ([]model.Finding, error) {
	var findings []model.Finding
	for _, c := range bl.Checks {
		if !c.AppliesTo(obj.Ref.Kind) {
			continue
		}
		pass, err := baseline.Eval(c, obj)
		if err != nil {
			return nil, err
		}
		f := model.Finding{
			CheckID:         c.ID,
			BaselineVersion: bl.Version,
			Ref:             obj.Ref,
			Severity:        c.Severity,
			Status:          model.StatusFail,
			Message:         c.Message,
		}
		if pass {
			f.Status = model.StatusPass
			f.Message = ""
		}
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].CheckID < findings[j].CheckID })
	return findings, nil
}

// SortFindings 按 (CheckID, 对象键) 排序，保证输出确定。
func SortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].CheckID != findings[j].CheckID {
			return findings[i].CheckID < findings[j].CheckID
		}
		return findings[i].Ref.Key() < findings[j].Ref.Key()
	})
}

// ApplyExemptions 把生效豁免套用到结论上（fail -> exempt），纯函数。
func ApplyExemptions(findings []model.Finding, exemptions []exemption.Exemption) {
	exempt := map[string]bool{}
	for _, e := range exemptions {
		exempt[e.CheckID+"|"+e.Ref.Key()] = true
	}
	for i := range findings {
		if findings[i].Status == model.StatusFail && exempt[findings[i].CheckID+"|"+findings[i].Ref.Key()] {
			findings[i].Status = model.StatusExempt
		}
	}
}

// Run 对全部对象并发执行基线检查，返回确定性排序的完整结论。
func Run(objs []model.Object, bl *baseline.Baseline, opts Options) (*Result, error) {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	perObj := make([][]model.Finding, len(objs))
	errs := make([]error, len(objs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i, o := range objs {
		wg.Add(1)
		go func(i int, o model.Object) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			f, err := EvalObject(bl, o)
			perObj[i] = f
			errs[i] = err
		}(i, o)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("evaluate: %w", err)
		}
	}
	var findings []model.Finding
	for _, f := range perObj {
		findings = append(findings, f...)
	}
	SortFindings(findings)
	ApplyExemptions(findings, opts.Exemptions)
	return &Result{BaselineVersion: bl.Version, Findings: findings}, nil
}
