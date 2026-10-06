// Package scan 编排全量扫描、增量复核与断点恢复。
//
// 不变式：
//   - 单对象结论是 (对象内容, 基线版本) 的纯函数，可缓存复用；
//   - 状态按对象粒度原子提交，中断不会留下半成品结论；
//   - 恢复 = 复用已提交对象 + 重算未提交对象，结果与一次性跑完逐条一致；
//   - 快照中已消失的对象不会进入新状态，其旧结论随之回收；
//   - 基线版本切换会使全部缓存失效，只有显式切换版本才改变结论。
package scan

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/engine"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/exemption"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/state"
)

// Scanner 是增量扫描器。
type Scanner struct {
	Baseline    *baseline.Baseline
	StatePath   string // 状态文件路径；为空则不持久化（纯全量）
	Exemptions  []exemption.Exemption
	Concurrency int
	// CommitEvery 控制断点提交粒度：每求值多少个对象提交一次状态；
	// <=0 时仅在结束时提交一次。
	CommitEvery int
}

// Scan 对给定对象集合执行（增量）扫描，返回与全量重扫逐条一致的结论。
func (s *Scanner) Scan(objs []model.Object) (*engine.Result, error) {
	store := state.New(s.Baseline.Version)
	if s.StatePath != "" {
		loaded, err := state.Load(s.StatePath)
		if err != nil {
			return nil, err
		}
		if loaded.BaselineVersion == s.Baseline.Version {
			store = loaded
		}
		// 版本不一致：丢弃旧缓存，全量重估（结论只能因显式切换版本而改变）。
	}

	concurrency := s.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	// 第一遍：划分"可复用"与"待求值"。
	pending := map[int]bool{}
	hashes := make([]string, len(objs))
	for i, o := range objs {
		h := state.HashObject(o)
		hashes[i] = h
		if prev, ok := store.Objects[o.Ref.Key()]; !ok || prev.Hash != h {
			pending[i] = true
		}
	}

	// 并发求值待处理对象；结果按索引落回，与调度顺序无关。
	evaluated := make([][]model.Finding, len(objs))
	errs := make([]error, len(objs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i := range objs {
		if !pending[i] {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			f, err := engine.EvalObject(s.Baseline, objs[i])
			evaluated[i] = f
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("evaluate: %w", err)
		}
	}

	// 重建状态：仅包含当前快照中的对象（旧对象结论在此回收），
	// 按对象键顺序周期性原子提交，支持断点恢复。
	next := state.New(s.Baseline.Version)
	commitEvery := s.CommitEvery
	dirty := 0
	commit := func() error {
		if s.StatePath == "" {
			return nil
		}
		return next.Save(s.StatePath)
	}
	for i, o := range objs {
		st := state.ObjectState{Hash: hashes[i]}
		if pending[i] {
			st.Findings = evaluated[i]
			dirty++
		} else {
			st.Findings = store.Objects[o.Ref.Key()].Findings
		}
		next.Objects[o.Ref.Key()] = st
		if commitEvery > 0 && dirty > 0 && dirty%commitEvery == 0 {
			if err := commit(); err != nil {
				return nil, err
			}
		}
	}
	if err := commit(); err != nil {
		return nil, err
	}

	// 汇总：对象键有序 -> 结论有序 -> 套用豁免（纯函数后处理）。
	var findings []model.Finding
	for _, o := range objs {
		findings = append(findings, next.Objects[o.Ref.Key()].Findings...)
	}
	engine.SortFindings(findings)
	engine.ApplyExemptions(findings, s.Exemptions)
	return &engine.Result{BaselineVersion: s.Baseline.Version, Findings: findings}, nil
}
