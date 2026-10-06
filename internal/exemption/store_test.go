package exemption

import (
	"testing"
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
)

func fixedClock() (func() time.Time, *time.Time) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return now }, &now
}

func sampleExpiry(now time.Time) time.Time { return now.Add(24 * time.Hour) }

func TestGrantActiveExpiryAndRevoke(t *testing.T) {
	dir := t.TempDir() + "/ex.json"
	clk, now := fixedClock()
	store, err := OpenStore(dir, WithClock(clk), WithAdmins("root"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := store.Grant("root", Exemption{
		CheckID: "C-001", ObjectKind: "Pod", Namespace: "ns", Name: "p",
		Reason: "breakglass", ExpiresAt: sampleExpiry(*now),
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	k := finding.Key{CheckID: "C-001", ObjectKind: object.KindPod, Namespace: "ns", Name: "p"}
	if got := store.Active(k, *now); len(got) != 1 {
		t.Fatalf("active at grant time = %d want 1", len(got))
	}
	// Expired exemption no longer suppresses.
	if got := store.Active(k, now.Add(25*time.Hour)); len(got) != 0 {
		t.Fatalf("active after expiry = %d want 0", len(got))
	}
	// Before creation window is not active.
	if got := store.Active(k, now.Add(-time.Hour)); len(got) != 0 {
		t.Fatalf("active before creation = %d want 0", len(got))
	}
	// Binding is exact: different object/check never matches.
	other := finding.Key{CheckID: "C-002", ObjectKind: object.KindPod, Namespace: "ns", Name: "p"}
	if got := store.Active(other, *now); len(got) != 0 {
		t.Fatal("exemption leaked to another check")
	}
	// Revoke.
	if err := store.Revoke("root", e.ID, *now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := store.Active(k, *now); len(got) != 0 {
		t.Fatal("revoked exemption still active")
	}
}

func TestUnauthorizedGrantAndRevokeAreDeniedAndAudited(t *testing.T) {
	dir := t.TempDir() + "/ex.json"
	clk, now := fixedClock()
	store, err := OpenStore(dir, WithClock(clk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant("mallory", Exemption{
		CheckID: "C-001", ObjectKind: "Pod", Name: "p", ExpiresAt: sampleExpiry(*now),
	}); err == nil {
		t.Fatal("unauthorized grant must be rejected")
	} else {
		var pe *PermissionError
		if !asPermission(err, &pe) {
			t.Fatalf("want PermissionError got %T %v", err, err)
		}
	}
	if err := store.Revoke("mallory", "EX-nope", *now); err == nil {
		t.Fatal("unauthorized revoke must be rejected")
	}
	audit := store.Audit()
	var denies int
	for _, a := range audit {
		if a.Denied {
			denies++
		}
	}
	if denies != 2 {
		t.Fatalf("denied audit records = %d want 2 (audit=%+v)", denies, audit)
	}
	// Nothing was created.
	if len(store.All()) != 0 {
		t.Fatal("denied grant must not persist an exemption")
	}
}

func TestGrantAutoFillsCreationTime(t *testing.T) {
	dir := t.TempDir() + "/ex.json"
	clk, now := fixedClock()
	store, _ := OpenStore(dir, WithClock(clk))
	// No CreatedAt supplied: it defaults to the current clock; a future expiry
	// relative to real/current time must be accepted.
	e, err := store.Grant("admin", Exemption{
		CheckID: "C", ObjectKind: "Pod", Name: "p",
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("grant with auto-filled CreatedAt should succeed: %v", err)
	}
	if !e.CreatedAt.Equal(*now) {
		t.Fatalf("CreatedAt = %v want %v", e.CreatedAt, *now)
	}
}

func TestCannotGrantAlreadyExpired(t *testing.T) {
	dir := t.TempDir() + "/ex.json"
	clk, now := fixedClock()
	store, _ := OpenStore(dir, WithClock(clk))
	if _, err := store.Grant("admin", Exemption{
		CheckID: "C", ObjectKind: "Pod", Name: "p",
		CreatedAt: *now, ExpiresAt: now.Add(-time.Minute),
	}); err == nil {
		t.Fatal("granting an already-expired exemption must fail")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := t.TempDir() + "/sub/ex.json"
	clk, now := fixedClock()
	s1, _ := OpenStore(path, WithClock(clk))
	e, err := s1.Grant("admin", Exemption{
		CheckID: "C-001", ObjectKind: "Pod", Name: "p", ExpiresAt: sampleExpiry(*now),
	})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(path, WithClock(clk))
	if err != nil {
		t.Fatal(err)
	}
	k := finding.Key{CheckID: "C-001", ObjectKind: object.KindPod, Name: "p"}
	if got := s2.Active(k, *now); len(got) != 1 || got[0].ID != e.ID {
		t.Fatal("exemption did not survive reopen")
	}
}

func asPermission(err error, target **PermissionError) bool {
	pe, ok := err.(*PermissionError)
	if ok {
		*target = pe
	}
	return ok
}
