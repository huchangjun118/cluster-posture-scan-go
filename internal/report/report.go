// Package report 输出逐字节稳定的结论报表。
//
// 稳定性保证：结论在引擎层已按 (CheckID, 对象键) 排序；
// 报表不含时间戳等易变字段；序列化使用固定缩进的结构体
// （字段顺序固定），空列表输出为 [] 而非 null。同一份快照在
// 同一基线版本下的报表字节完全一致，可直接纳入自动化校验。
package report

import (
	"bytes"
	"encoding/json"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/engine"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

// Summary 按严重度分级汇总（仅统计 fail 结论）。
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Pass     int `json:"pass"`
	Exempt   int `json:"exempt"`
}

// Document 是报表顶层结构。
type Document struct {
	BaselineVersion string          `json:"baselineVersion"`
	Summary         Summary         `json:"summary"`
	Findings        []model.Finding `json:"findings"`
}

// Render 输出稳定的 JSON 报表字节流。
func Render(res *engine.Result) ([]byte, error) {
	findings := res.Findings
	if findings == nil {
		findings = []model.Finding{}
	}
	doc := Document{
		BaselineVersion: res.BaselineVersion,
		Summary:         Summarize(findings),
		Findings:        findings,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Summarize 统计结论：fail 按严重度分级计数，pass/exempt 单独计数。
func Summarize(findings []model.Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Status {
		case model.StatusFail:
			switch f.Severity {
			case model.SeverityCritical:
				s.Critical++
			case model.SeverityHigh:
				s.High++
			case model.SeverityMedium:
				s.Medium++
			case model.SeverityLow:
				s.Low++
			}
		case model.StatusPass:
			s.Pass++
		case model.StatusExempt:
			s.Exempt++
		}
	}
	return s
}
