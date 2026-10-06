package exemption

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

func newStore() *Store {
	return &Store{Approvers: []string{"sec-admin"}}
}

func sample(id string, expires time.Time) Exemption {
	return Exemption{
		ID:      id,
		CheckID: "no-privileged",
		Ref:     model.ObjectRef{Kind: "Pod", Namespace: "ns", Name: "p1"},
		Reason:  "accepted risk",
		// CreatedBy 由 Register 按 actor 填写
		ExpiresAt: expires,
	}
}

func readAudit(t *testing.T, path string) []map[string]any {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
	return recs
}

// 越权登记被拒绝并留下审计记录。
func TestUnauthorizedRegisterDeniedAndAudited(t *testing.T) {
	s := newStore()
	audit := filepath.Join(t.TempDir(), "audit.log")
	err := s.Register(sample("e1", time.Now().Add(time.Hour)), "intruder", audit)
	if err == nil {
		t.Fatal("expected denial for unauthorized actor")
	}
	if len(s.Exemptions) != 0 {
		t.Fatal("denied exemption must not be stored")
	}
	recs := readAudit(t, audit)
	if len(recs) != 1 || recs[0]["decision"] != "denied" || recs[0]["actor"] != "intruder" || recs[0]["action"] != "register" {
		t.Fatalf("audit record missing or wrong: %v", recs)
	}
}

// 越权撤销被拒绝并留下审计记录。
func TestUnauthorizedRevokeDeniedAndAudited(t *testing.T) {
	s := newStore()
	audit := filepath.Join(t.TempDir(), "audit.log")
	if err := s.Register(sample("e1", time.Now().Add(time.Hour)), "sec-admin", audit); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke("e1", "intruder", audit); err == nil {
		t.Fatal("expected denial for unauthorized revoke")
	}
	if s.Exemptions[0].Revoked {
		t.Fatal("denied revoke must not take effect")
	}
	recs := readAudit(t, audit)
	if len(recs) != 2 || recs[1]["decision"] != "denied" || recs[1]["action"] != "revoke" {
		t.Fatalf("audit records wrong: %v", recs)
	}
}

// 合法登记与撤销均留痕。
func TestAuthorizedFlowAudited(t *testing.T) {
	s := newStore()
	audit := filepath.Join(t.TempDir(), "audit.log")
	if err := s.Register(sample("e1", time.Now().Add(time.Hour)), "sec-admin", audit); err != nil {
		t.Fatal(err)
	}
	if s.Exemptions[0].CreatedBy != "sec-admin" {
		t.Fatal("CreatedBy should be set from actor")
	}
	if err := s.Revoke("e1", "sec-admin", audit); err != nil {
		t.Fatal(err)
	}
	if !s.Exemptions[0].Revoked {
		t.Fatal("exemption should be revoked")
	}
	recs := readAudit(t, audit)
	if len(recs) != 2 || recs[0]["decision"] != "allowed" || recs[1]["decision"] != "allowed" {
		t.Fatalf("audit records wrong: %v", recs)
	}
}

// 过期与已撤销的豁免不生效；重复 ID 被拒绝。
func TestActiveFiltering(t *testing.T) {
	s := newStore()
	now := time.Now()
	s.Exemptions = []Exemption{
		sample("active", now.Add(time.Hour)),
		sample("expired", now.Add(-time.Minute)),
		sample("revoked", now.Add(time.Hour)),
	}
	s.Exemptions[2].Revoked = true
	active := s.Active(now)
	if len(active) != 1 || active[0].ID != "active" {
		t.Fatalf("expected only active exemption, got %v", active)
	}
	if err := s.Register(sample("active", now.Add(time.Hour)), "sec-admin", ""); err == nil {
		t.Fatal("duplicate id should be rejected")
	}
}

// 持久化往返。
func TestSaveLoadRoundTrip(t *testing.T) {
	s := newStore()
	p := filepath.Join(t.TempDir(), "exemptions.json")
	if err := s.Register(sample("e1", time.Now().Add(time.Hour)), "sec-admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Exemptions) != 1 || len(loaded.Approvers) != 1 {
		t.Fatalf("round trip failed: %+v", loaded)
	}
}
