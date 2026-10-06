package exemption

import (
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
)

// Exemption suppresses one check for one object within a bounded time window.
// It never applies to any other check or object: both are bound explicitly.
type Exemption struct {
	ID         string     `json:"id"`
	CheckID    string     `json:"check_id"`
	ObjectKind string     `json:"object_kind"`
	Namespace  string     `json:"namespace"`
	Name       string     `json:"name"`
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
}

// Active reports whether the exemption is in force at time t: it must not be
// revoked and t must be within [CreatedAt, ExpiresAt). An expiry exactly equal
// to t is treated as expired.
func (e *Exemption) Active(t time.Time) bool {
	if e.RevokedAt != nil {
		return false
	}
	if t.Before(e.CreatedAt) {
		return false
	}
	return t.Before(e.ExpiresAt)
}

// Key is the (check, object) binding of an exemption.
type Key struct {
	CheckID    string
	ObjectKind string
	Namespace  string
	Name       string
}

// Key returns the binding.
func (e *Exemption) Key() Key {
	return Key{CheckID: e.CheckID, ObjectKind: e.ObjectKind, Namespace: e.Namespace, Name: e.Name}
}

// Matches reports whether the exemption applies to finding key k.
func (e *Exemption) Matches(k finding.Key) bool {
	return e.CheckID == k.CheckID &&
		e.ObjectKind == string(k.ObjectKind) &&
		e.Namespace == k.Namespace &&
		e.Name == k.Name
}
