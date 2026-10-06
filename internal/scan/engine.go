package scan

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/exemption"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
)

// Config holds scanner parameters.
type Config struct {
	Workers     int
	StateDir    string
	BaselineVer baseline.Version
	// AsOf is the evaluation time used for exemption expiry and finding
	// timestamps. When zero, the engine clock is used. Fixing it makes reports
	// byte-reproducible.
	AsOf time.Time
	// CommitEvery bounds how many units complete between atomic checkpoints.
	// Zero means commit after each unit (safest, slowest).
	CommitEvery int
}

// Engine evaluates a snapshot against a baseline with resumable, incremental
// review. Output ordering never depends on worker scheduling or worker count.
type Engine struct {
	registry   *baseline.Registry
	exemptions *exemption.Store
	cfg        Config
	now        func() time.Time
	// failAfter is a test hook: interrupt after this many further units
	// complete. Zero disables it.
	failAfter int
}

// Option customizes an Engine.
type Option func(*Engine)

// WithClock overrides the engine clock.
func WithClock(c func() time.Time) Option { return func(e *Engine) { e.now = c } }

// WithFailureInjection forces an interruption after n units complete.
func WithFailureInjection(n int) Option { return func(e *Engine) { e.failAfter = n } }

// NewEngine constructs an Engine.
func NewEngine(reg *baseline.Registry, ex *exemption.Store, cfg Config, opts ...Option) *Engine {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	e := &Engine{registry: reg, exemptions: ex, cfg: cfg, now: time.Now}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Result is the outcome of a scan (full or incremental).
type Result struct {
	SnapshotID  string             `json:"snapshot_id"`
	Baseline    baseline.Version   `json:"baseline"`
	EvaluatedAt string             `json:"evaluated_at"`
	Findings    []*finding.Finding `json:"findings"`
	Summary     finding.Summary    `json:"summary"`
	Incremental bool               `json:"incremental"`
	Revoked     []finding.Key      `json:"revoked"`
}

// evalOutcome is one fully evaluated unit.
type evalOutcome struct {
	unit    string
	objFP   string
	finding *finding.Finding // nil when compliant
}

// location is the (check, object) a unit consists of.
type location struct {
	checkID string
	obj     object.Key
}

// plan is the deterministic work list for one scan.
type plan struct {
	units  []string
	byUnit map[string]location
}

// buildPlan enumerates applicable (check, object) units in total order:
// checks by ID, then objects by key within each check.
func buildPlan(b *baseline.Baseline, snap *object.Snapshot) *plan {
	p := &plan{byUnit: map[string]location{}}
	checks := append([]*baseline.Check(nil), b.Checks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
	keys := snap.Keys()
	for _, c := range checks {
		for _, k := range keys {
			if k.Kind != c.Kind {
				continue
			}
			u := unitKey(c.ID, k)
			p.units = append(p.units, u)
			p.byUnit[u] = location{checkID: c.ID, obj: k}
		}
	}
	return p
}

// FullScan evaluates every object of the snapshot. Resumable: continuing after
// an interruption yields exactly the result of one uninterrupted run.
func (e *Engine) FullScan(snap *object.Snapshot) (*Result, error) {
	return e.run(snap, false)
}

// ReviewIncrementally re-evaluates only objects changed since the last
// committed review and reclaims findings of vanished objects. Its output is
// identical to FullScan over the same snapshot.
func (e *Engine) ReviewIncrementally(snap *object.Snapshot) (*Result, error) {
	return e.run(snap, true)
}

func (e *Engine) run(snap *object.Snapshot, incremental bool) (*Result, error) {
	b, err := e.registry.Get(e.cfg.BaselineVer)
	if err != nil {
		return nil, err
	}
	asOf := e.cfg.AsOf
	if asOf.IsZero() {
		asOf = e.now()
	}
	asOf = asOf.UTC()

	store := newStateStore(e.cfg.StateDir)
	st, err := store.load(string(b.Version))
	if err != nil {
		return nil, err
	}
	// A full scan of a different snapshot (or the first scan) starts the
	// review stream over; an incremental review carries reusable state.
	if !incremental && st.SnapshotID != "" && st.SnapshotID != snap.ID() {
		st = &stateFile{Baseline: string(b.Version), UnitFP: map[string]string{}}
	}

	p := buildPlan(b, snap)
	valid := map[string]bool{}
	fp := map[string]string{}    // unit -> current object fingerprint
	exSig := map[string]string{} // unit -> current active-exemption signature
	for _, u := range p.units {
		valid[u] = true
		loc := p.byUnit[u]
		fp[u] = snap.Get(loc.obj).Fingerprint()
		exSig[u] = e.exemptionSignature(b, loc, asOf)
	}

	findingsByUnit := map[string]*finding.Finding{}
	var revoked []finding.Key
	for _, f := range st.Findings {
		u := unitKey(f.CheckID, object.Key{Kind: f.ObjectKind, Namespace: f.Namespace, Name: f.Name})
		findingsByUnit[u] = f
	}

	// Decide which units are trustworthy already.
	done := map[string]bool{}
	for u, oldFP := range st.UnitFP {
		if !valid[u] {
			// Unit vanished (object deleted or no longer applicable): reclaim.
			if f, ok := findingsByUnit[u]; ok {
				revoked = append(revoked, f.Key())
			}
			delete(findingsByUnit, u)
			continue
		}
		sameObject := oldFP == fp[u]
		sameExemption := st.UnitEx[u] == exSig[u]
		reusable := sameObject && sameExemption
		if !incremental && st.SnapshotID != snap.ID() {
			// Full scan of a new snapshot starts the review stream over.
			reusable = false
		}
		if reusable {
			done[u] = true
			continue
		}
		// Stale (object changed, exemption expired/revoked, or new snapshot):
		// drop any finding so the unit is freshly evaluated.
		delete(findingsByUnit, u)
	}

	var pending []string
	for _, u := range p.units {
		if !done[u] {
			pending = append(pending, u)
		}
	}

	outcomes, interrupted := e.evaluate(b, snap, pending, asOf, store, st, p, fp, exSig, findingsByUnit)
	for _, oc := range outcomes {
		if oc.finding != nil {
			findingsByUnit[oc.unit] = oc.finding
		} else {
			delete(findingsByUnit, oc.unit)
		}
	}
	allDone := appendDone(done, outcomes)

	if err := e.commit(store, st, p, snap, b, findingsByUnit, allDone, fp, exSig); err != nil {
		return nil, err
	}
	if interrupted != nil {
		return nil, &InterruptedError{Cause: interrupted}
	}

	final, err := store.load(string(b.Version))
	if err != nil {
		return nil, err
	}
	findings := append([]*finding.Finding(nil), final.Findings...)
	finding.Sort(findings)
	sort.Slice(revoked, func(i, j int) bool { return unitKeyOf(revoked[i]) < unitKeyOf(revoked[j]) })
	return &Result{
		SnapshotID:  snap.ID(),
		Baseline:    b.Version,
		EvaluatedAt: asOf.Format(time.RFC3339Nano),
		Findings:    findings,
		Summary:     finding.Summarize(findings),
		Incremental: incremental,
		Revoked:     revoked,
	}, nil
}

func unitKeyOf(k finding.Key) string {
	return unitKey(k.CheckID, object.Key{Kind: k.ObjectKind, Namespace: k.Namespace, Name: k.Name})
}

// exemptionSignature is the deterministic signature of all exemptions active
// for a unit at asOf: the sorted, comma-joined exemption IDs. The empty string
// means "no active exemption", so grant/expiry/revocation all change it.
func (e *Engine) exemptionSignature(b *baseline.Baseline, loc location, asOf time.Time) string {
	if e.exemptions == nil {
		return ""
	}
	check := findCheck(b, loc.checkID)
	k := finding.Key{
		CheckID:    loc.checkID,
		ObjectKind: check.Kind,
		Namespace:  loc.obj.Namespace,
		Name:       loc.obj.Name,
	}
	active := e.exemptions.Active(k, asOf)
	ids := make([]string, 0, len(active))
	for _, x := range active {
		ids = append(ids, x.ID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func appendDone(done map[string]bool, outcomes []*evalOutcome) map[string]bool {
	out := map[string]bool{}
	for k, v := range done {
		out[k] = v
	}
	for _, oc := range outcomes {
		out[oc.unit] = true
	}
	return out
}

// evaluate runs pending units concurrently and checkpoints completed batches
// atomically. Only fully completed units are checkpointed, so a crash leaves
// no half conclusion.
func (e *Engine) evaluate(
	b *baseline.Baseline,
	snap *object.Snapshot,
	pending []string,
	asOf time.Time,
	store *stateStore,
	st *stateFile,
	p *plan,
	fp map[string]string,
	exSig map[string]string,
	acc map[string]*finding.Finding,
) ([]*evalOutcome, error) {
	batch := e.cfg.CommitEvery
	if batch <= 0 {
		batch = 1
	}
	var (
		mu          sync.Mutex
		wg          sync.WaitGroup
		sem         = make(chan struct{}, e.cfg.Workers)
		completed   []*evalOutcome
		interrupted error
	)

	flushBatch := func() error {
		findings := map[string]*finding.Finding{}
		for k, v := range acc {
			findings[k] = v
		}
		done := map[string]bool{}
		for _, oc := range completed {
			done[oc.unit] = true
			if oc.finding != nil {
				findings[oc.unit] = oc.finding
			} else {
				delete(findings, oc.unit)
			}
		}
		return e.commit(store, st, p, snap, b, findings, done, fp, exSig)
	}

	for _, u := range pending {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			mu.Lock()
			if interrupted != nil {
				mu.Unlock()
				return
			}
			mu.Unlock()

			oc := e.evaluateUnit(b, snap, p.byUnit[u], asOf)

			mu.Lock()
			defer mu.Unlock()
			if interrupted != nil {
				return
			}
			completed = append(completed, oc)
			if e.failAfter > 0 && len(completed) >= e.failAfter {
				interrupted = fmt.Errorf("injected interruption after %d units", len(completed))
				if err := flushBatch(); err != nil {
					interrupted = err
				}
				return
			}
			if len(completed)%batch == 0 {
				if err := flushBatch(); err != nil {
					interrupted = err
				}
			}
		}(u)
	}
	wg.Wait()
	return completed, interrupted
}

// evaluateUnit evaluates one (check, object) pair.
func (e *Engine) evaluateUnit(b *baseline.Baseline, snap *object.Snapshot, loc location, asOf time.Time) *evalOutcome {
	check := findCheck(b, loc.checkID)
	obj := snap.Get(loc.obj)
	oc := &evalOutcome{unit: unitKey(check.ID, loc.obj), objFP: obj.Fingerprint()}
	violates, msg := check.Evaluate(obj)
	if !violates {
		return oc
	}
	f := &finding.Finding{
		CheckID:     check.ID,
		ObjectKind:  check.Kind,
		Namespace:   loc.obj.Namespace,
		Name:        loc.obj.Name,
		Severity:    check.Severity,
		Message:     msg,
		Baseline:    string(b.Version),
		ObjectFP:    obj.Fingerprint(),
		EvaluatedAt: asOf.Format(time.RFC3339Nano),
		Status:      finding.StatusOpen,
	}
	if e.exemptions != nil && len(e.exemptions.Active(f.Key(), asOf)) > 0 {
		f.Status = finding.StatusSuppressed
	}
	oc.finding = f
	return oc
}

// commit writes the authoritative review state, rebuilt in plan order. Units
// outside the plan are dropped, reclaiming findings of vanished objects.
// "done" merges over already-stored progress (batch checkpoints).
func (e *Engine) commit(
	store *stateStore,
	st *stateFile,
	p *plan,
	snap *object.Snapshot,
	b *baseline.Baseline,
	findingsByUnit map[string]*finding.Finding,
	done map[string]bool,
	fp map[string]string,
	exSig map[string]string,
) error {
	unitFP := map[string]string{}
	for u, v := range st.UnitFP {
		unitFP[u] = v
	}
	unitEx := map[string]string{}
	for u, v := range st.UnitEx {
		unitEx[u] = v
	}
	for u := range done {
		if v, ok := fp[u]; ok {
			unitFP[u] = v
		}
		if v, ok := exSig[u]; ok && v != "" {
			unitEx[u] = v
		} else {
			delete(unitEx, u)
		}
	}
	for u := range unitFP {
		if _, ok := fp[u]; !ok {
			delete(unitFP, u)
			delete(unitEx, u)
		}
	}
	st.SnapshotID = snap.ID()
	st.Baseline = string(b.Version)
	st.UnitFP = unitFP
	st.UnitEx = unitEx
	st.Findings = st.Findings[:0]
	for _, u := range p.units {
		if f, ok := findingsByUnit[u]; ok {
			st.Findings = append(st.Findings, f)
		}
	}
	return store.commit(st)
}

func findCheck(b *baseline.Baseline, id string) *baseline.Check {
	for _, c := range b.Checks {
		if c.ID == id {
			return c

		}
	}
	return nil
}

// InterruptedError signals that a scan stopped early; committed progress is
// safe to resume from.
type InterruptedError struct{ Cause error }

func (e *InterruptedError) Error() string { return fmt.Sprintf("scan interrupted: %v", e.Cause) }
func (e *InterruptedError) Unwrap() error { return e.Cause }
