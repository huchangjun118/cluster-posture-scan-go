package exemption

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
)

// Action tags an audit record.
type Action string

const (
	ActionGrant  Action = "grant"
	ActionRevoke Action = "revoke"
)

// AuditEntry records one administrative operation, including rejected ones.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action Action    `json:"action"`
	Denied bool      `json:"denied"`
	Target string    `json:"target"`
	Reason string    `json:"reason"`
}

// storeFile is the on-disk representation.
type storeFile struct {
	Exemptions []*Exemption `json:"exemptions"`
	Audit      []AuditEntry `json:"audit"`
}

// Store persists exemptions and an append-only audit trail. All mutations are
// serialized and atomically written; audit records are never dropped,
// including denials.
type Store struct {
	mu    sync.Mutex
	path  string
	now   func() time.Time
	admin map[string]bool // actors allowed to grant/revoke

	exemptions map[string]*Exemption
	audit      []AuditEntry
}

// Option customizes a Store.
type Option func(*Store)

// WithClock overrides the clock (mainly for tests).
func WithClock(c func() time.Time) Option {
	return func(s *Store) { s.now = c }
}

// WithAdmins sets the set of actors permitted to grant and revoke.
func WithAdmins(actors ...string) Option {
	return func(s *Store) {
		for _, a := range actors {
			s.admin[a] = true
		}
	}
}

// OpenStore loads (or initializes) the exemption store at path. By default the
// single actor "admin" is privileged.
func OpenStore(path string, opts ...Option) (*Store, error) {
	s := &Store{
		path:       path,
		now:        time.Now,
		admin:      map[string]bool{"admin": true},
		exemptions: map[string]*Exemption{},
	}
	for _, o := range opts {
		o(s)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create exemption state dir: %w", err)
	}
	if b, err := os.ReadFile(path); err == nil {
		var f storeFile
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("parse exemption store: %w", err)
		}
		for _, e := range f.Exemptions {
			s.exemptions[e.ID] = e
		}
		s.audit = f.Audit
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// Grant registers an exemption. It is validated, permission checked and
// audited. The returned exemption carries the assigned ID.
func (s *Store) Grant(actor string, e Exemption) (*Exemption, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := func(denied bool, target, reason string) {
		s.audit = append(s.audit, AuditEntry{
			Time: s.now().UTC(), Actor: actor, Action: ActionGrant,
			Denied: denied, Target: target, Reason: reason,
		})
	}
	if !s.admin[actor] {
		record(true, e.CheckID+":"+e.Name, "actor is not authorized to grant exemptions")
		return nil, &PermissionError{Actor: actor, Op: "grant"}
	}
	if e.CheckID == "" || e.ObjectKind == "" || e.Name == "" {
		record(true, e.CheckID, "exemption must bind check, object kind and name")
		return nil, fmt.Errorf("exemption must bind check, object kind and name")
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = s.now()
	}
	if !e.ExpiresAt.After(e.CreatedAt) {
		record(true, e.CheckID+":"+e.Name, "expiry must be after creation time")
		return nil, fmt.Errorf("expiry must be after creation time")
	}
	if !s.now().Before(e.ExpiresAt) {
		record(true, e.CheckID+":"+e.Name, "refusing to grant an already expired exemption")
		return nil, fmt.Errorf("exemption already expired at grant time")
	}
	e.ID = s.deriveID(&e)
	e.CreatedBy = actor
	if _, exists := s.exemptions[e.ID]; exists {
		record(false, e.ID, "identical exemption already registered")
		return s.exemptions[e.ID], nil
	}
	cp := e
	s.exemptions[e.ID] = &cp
	record(false, e.ID, "granted")
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &cp, nil
}

// Revoke marks an exemption revoked. It is permission checked and audited.
// Revoking an unknown exemption is rejected and recorded.
func (s *Store) Revoke(actor, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	deny := func(reason string) error {
		s.audit = append(s.audit, AuditEntry{
			Time: s.now().UTC(), Actor: actor, Action: ActionRevoke,
			Denied: true, Target: id, Reason: reason,
		})
		_ = s.persistLocked()
		if !s.admin[actor] {
			return &PermissionError{Actor: actor, Op: "revoke"}
		}
		return fmt.Errorf("%s", reason)
	}
	if !s.admin[actor] {
		return deny("actor is not authorized to revoke exemptions")
	}
	e, ok := s.exemptions[id]
	if !ok {
		return deny("unknown exemption id")
	}
	if e.RevokedAt != nil {
		s.audit = append(s.audit, AuditEntry{
			Time: s.now().UTC(), Actor: actor, Action: ActionRevoke,
			Denied: false, Target: id, Reason: "already revoked",
		})
		return s.persistLocked()
	}
	when := at
	if when.IsZero() {
		when = s.now()
	}
	e.RevokedAt = &when
	e.RevokedBy = actor
	s.audit = append(s.audit, AuditEntry{
		Time: s.now().UTC(), Actor: actor, Action: ActionRevoke,
		Denied: false, Target: id, Reason: "revoked",
	})
	return s.persistLocked()
}

// Active returns exemptions matching k that are in force at t, sorted by ID.
// Expired or revoked exemptions never suppress.
func (s *Store) Active(k finding.Key, t time.Time) []*Exemption {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Exemption
	for _, e := range s.exemptions {
		if e.Matches(k) && e.Active(t.UTC()) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// All returns all registered exemptions sorted by ID.
func (s *Store) All() []*Exemption {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Exemption, 0, len(s.exemptions))
	for _, e := range s.exemptions {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Audit returns the audit trail in append order.
func (s *Store) Audit() []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEntry(nil), s.audit...)
}

// deriveID assigns a deterministic id from the binding and validity window, so
// re-registering the same exemption is idempotent and never doubles up.
func (s *Store) deriveID(e *Exemption) string {
	raw := strings.Join([]string{
		e.CheckID, e.ObjectKind, e.Namespace, e.Name,
		e.CreatedAt.UTC().Format(time.RFC3339Nano),
		e.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return "EX-" + hex.EncodeToString(sum[:12])
}

// persistLocked writes the store atomically: temp file in the same directory,
// fsync, rename. Readers therefore never observe a half-written file.
func (s *Store) persistLocked() error {
	f := storeFile{Audit: s.audit}
	ids := make([]string, 0, len(s.exemptions))
	for id := range s.exemptions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		f.Exemptions = append(f.Exemptions, s.exemptions[id])
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".exemptions-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// PermissionError describes a rejected administrative operation.
type PermissionError struct {
	Actor string
	Op    string
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("actor %q is not permitted to %s exemptions", e.Actor, e.Op)
}
