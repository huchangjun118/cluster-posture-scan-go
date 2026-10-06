package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/scan"
)

// Format selects a renderer.
type Format string

const (
	// FormatJSON is the byte-stable canonical report, suitable for automated
	// verification of identical snapshot+baseline inputs.
	FormatJSON Format = "json"
	// FormatText is a human-readable rendering.
	FormatText Format = "text"
)

// Options controls report rendering.
type Options struct {
	Format Format
}

// reportDoc is the fixed JSON shape. Field order is fixed by struct order and
// map keys are sorted explicitly, so output is byte-stable.
type reportDoc struct {
	SnapshotID  string          `json:"snapshot_id"`
	Baseline    string          `json:"baseline"`
	EvaluatedAt string          `json:"evaluated_at"`
	Incremental bool            `json:"incremental"`
	Summary     summaryDoc      `json:"summary"`
	Findings    []findingDoc    `json:"findings"`
	Revoked     []findingRefDoc `json:"revoked,omitempty"`
}

type summaryDoc struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[string]int `json:"by_status"`
}

type findingDoc struct {
	CheckID     string `json:"check_id"`
	ObjectKind  string `json:"object_kind"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	Baseline    string `json:"baseline"`
	ObjectFP    string `json:"object_fingerprint"`
	EvaluatedAt string `json:"evaluated_at"`
}

type findingRefDoc struct {
	CheckID    string `json:"check_id"`
	ObjectKind string `json:"object_kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

// Write renders a scan result. Identical (snapshot, baseline, evaluation time)
// input always produces identical bytes.
func Write(w io.Writer, r *scan.Result, opts Options) error {
	if opts.Format == "" {
		opts.Format = FormatJSON
	}
	switch opts.Format {
	case FormatJSON:
		return writeJSON(w, r)
	case FormatText:
		return writeText(w, r)
	default:
		return fmt.Errorf("unknown report format %q", opts.Format)
	}
}

func writeJSON(w io.Writer, r *scan.Result) error {
	doc := reportDoc{
		SnapshotID:  r.SnapshotID,
		Baseline:    string(r.Baseline),
		EvaluatedAt: r.EvaluatedAt,
		Incremental: r.Incremental,
		Summary: summaryDoc{
			Total:      r.Summary.Total,
			BySeverity: orderedSeverityCounts(r.Summary.BySeverity),
			ByStatus:   orderedStatusCounts(r.Summary.ByStatus),
		},
		Findings: make([]findingDoc, 0, len(r.Findings)),
	}
	for _, f := range r.Findings {
		doc.Findings = append(doc.Findings, findingDoc{
			CheckID: f.CheckID, ObjectKind: string(f.ObjectKind),
			Namespace: f.Namespace, Name: f.Name,
			Severity: string(f.Severity), Status: string(f.Status),
			Message: f.Message, Baseline: f.Baseline,
			ObjectFP: f.ObjectFP, EvaluatedAt: f.EvaluatedAt,
		})
	}
	for _, k := range r.Revoked {
		doc.Revoked = append(doc.Revoked, findingRefDoc{
			CheckID: k.CheckID, ObjectKind: string(k.ObjectKind),
			Namespace: k.Namespace, Name: k.Name,
		})
	}
	// json.Marshal already emits map keys sorted; findings are passed in
	// deterministic order from the engine. No trailing whitespace beyond a
	// single final newline so byte comparison is exact.
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func orderedSeverityCounts(in map[finding.Severity]int) map[string]int {
	out := map[string]int{}
	// Emit all severities, including zero counts, in fixed rank order so the
	// shape is stable even when a severity is absent.
	for _, sev := range []finding.Severity{
		finding.SeverityCritical, finding.SeverityHigh,
		finding.SeverityMedium, finding.SeverityLow,
	} {
		out[string(sev)] = in[sev]
	}
	return out
}

func orderedStatusCounts(in map[finding.Status]int) map[string]int {
	out := map[string]int{}
	for _, st := range []finding.Status{finding.StatusOpen, finding.StatusSuppressed} {
		out[string(st)] = in[st]
	}
	return out
}

func writeText(w io.Writer, r *scan.Result) error {
	var b strings.Builder
	fmt.Fprintf(&b, "snapshot: %s\n", r.SnapshotID)
	fmt.Fprintf(&b, "baseline: %s\n", r.Baseline)
	fmt.Fprintf(&b, "evaluated_at: %s\n", r.EvaluatedAt)
	sevs := []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow}
	var counts []string
	for _, s := range sevs {
		counts = append(counts, fmt.Sprintf("%s=%d", s, r.Summary.BySeverity[s]))
	}
	fmt.Fprintf(&b, "summary: total=%d (%s)\n", r.Summary.Total, strings.Join(counts, ", "))
	fmt.Fprintf(&b, "open=%d suppressed=%d\n",
		r.Summary.ByStatus[finding.StatusOpen],
		r.Summary.ByStatus[finding.StatusSuppressed])
	if len(r.Revoked) > 0 {
		rev := make([]string, 0, len(r.Revoked))
		for _, k := range r.Revoked {
			rev = append(rev, k.CheckID+":"+string(k.ObjectKind)+"/"+k.Namespace+"/"+k.Name)
		}
		sort.Strings(rev)
		fmt.Fprintf(&b, "reclaimed: %s\n", strings.Join(rev, ", "))
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s][%s] %s %s/%s/%s - %s\n",
			f.Severity, f.Status, f.CheckID, f.ObjectKind, f.Namespace, f.Name, f.Message)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
