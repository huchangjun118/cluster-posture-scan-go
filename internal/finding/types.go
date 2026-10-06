package finding

import (
	"sort"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
)

// Severity of a finding. The zero value is intentionally not a valid severity.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank defines the ordering used in summaries and reports
// (higher rank sorts first).
var severityRank = map[Severity]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Rank returns the numeric rank of a severity.
func (s Severity) Rank() int { return severityRank[s] }

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// Status of a finding.
type Status string

const (
	// StatusOpen is a live, non-suppressed non-compliant result.
	StatusOpen Status = "open"
	// StatusSuppressed is suppressed by an active exemption.
	StatusSuppressed Status = "suppressed"
)

// Finding is one evaluation result for one (check, object) pair.
type Finding struct {
	CheckID     string      `json:"check_id"`
	ObjectKind  object.Kind `json:"object_kind"`
	Namespace   string      `json:"namespace"`
	Name        string      `json:"name"`
	Severity    Severity    `json:"severity"`
	Message     string      `json:"message"`
	Status      Status      `json:"status"`
	Baseline    string      `json:"baseline"`
	ObjectFP    string      `json:"object_fingerprint"`
	EvaluatedAt string      `json:"evaluated_at"`
}

// Key is the deterministic identity of a finding: check + object.
type Key struct {
	CheckID    string
	ObjectKind object.Kind
	Namespace  string
	Name       string
}

// Key returns the finding identity.
func (f *Finding) Key() Key {
	return Key{CheckID: f.CheckID, ObjectKind: f.ObjectKind, Namespace: f.Namespace, Name: f.Name}
}

// Less defines the total deterministic ordering for findings:
// severity rank desc, then check id, kind, namespace, name.
func Less(a, b *Finding) bool {
	if ra, rb := a.Severity.Rank(), b.Severity.Rank(); ra != rb {
		return ra > rb
	}
	if a.CheckID != b.CheckID {
		return a.CheckID < b.CheckID
	}
	if a.ObjectKind != b.ObjectKind {
		return a.ObjectKind < b.ObjectKind
	}
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	return a.Name < b.Name
}

// Sort sorts findings in place using Less.
func Sort(fs []*Finding) { sort.Slice(fs, func(i, j int) bool { return Less(fs[i], fs[j]) }) }

// Summary counts findings by severity and status.
type Summary struct {
	BySeverity map[Severity]int `json:"by_severity"`
	ByStatus   map[Status]int   `json:"by_status"`
	Total      int              `json:"total"`
}

// Summarize builds a Summary over fs.
func Summarize(fs []*Finding) Summary {
	sum := Summary{BySeverity: map[Severity]int{}, ByStatus: map[Status]int{}}
	for _, f := range fs {
		sum.BySeverity[f.Severity]++
		sum.ByStatus[f.Status]++
		sum.Total++
	}
	return sum
}
