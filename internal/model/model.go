// Package model 定义扫描系统共享的核心数据类型。
package model

// ObjectRef 唯一标识一个集群对象。
type ObjectRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Key 返回对象的规范化键，用于排序与去重。
func (r ObjectRef) Key() string { return r.Kind + "/" + r.Namespace + "/" + r.Name }

// Object 是从快照读入并归一后的集群对象。
type Object struct {
	Ref    ObjectRef      `json:"ref"`
	Fields map[string]any `json:"fields"`
	// Source 记录归一后对象内容的来源文件（合并优先级最高者）。
	Source string `json:"source"`
}

// Severity 表示检查严重度。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Status 表示单条结论状态。
type Status string

const (
	StatusFail   Status = "fail"
	StatusPass   Status = "pass"
	StatusExempt Status = "exempt"
)

// Finding 是"检查 × 对象"的一条结论。
type Finding struct {
	CheckID         string    `json:"checkId"`
	BaselineVersion string    `json:"baselineVersion"`
	Ref             ObjectRef `json:"ref"`
	Severity        Severity  `json:"severity"`
	Status          Status    `json:"status"`
	Message         string    `json:"message,omitempty"`
}
