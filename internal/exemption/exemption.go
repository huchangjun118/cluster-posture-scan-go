// Package exemption 管理豁免的登记、撤销、到期与审计。
//
// 豁免绑定到具体 (检查, 对象)，带到期时间：过期或已撤销的豁免
// 不再压制结论。只有登记在案的授权主体可以登记或撤销豁免；
// 越权操作会被拒绝并追加到审计日志（JSONL，一行一条）。
package exemption

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

// Exemption 绑定一条检查与一个对象。
type Exemption struct {
	ID        string          `json:"id"`
	CheckID   string          `json:"checkId"`
	Ref       model.ObjectRef `json:"ref"`
	Reason    string          `json:"reason"`
	CreatedBy string          `json:"createdBy"`
	ExpiresAt time.Time       `json:"expiresAt"`
	Revoked   bool            `json:"revoked,omitempty"`
}

// Store 是豁免仓库。
type Store struct {
	// Approvers 为有权登记/撤销豁免的主体。
	Approvers  []string    `json:"approvers"`
	Exemptions []Exemption `json:"exemptions"`
}

// auditRecord 是一条审计记录。
type auditRecord struct {
	Time        time.Time `json:"time"`
	Actor       string    `json:"actor"`
	Action      string    `json:"action"` // register / revoke
	ExemptionID string    `json:"exemptionId"`
	Decision    string    `json:"decision"` // allowed / denied
	Reason      string    `json:"reason,omitempty"`
}

// Load 读取豁免文件；不存在时返回空仓库。
func Load(path string) (*Store, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Store{}, nil
		}
		return nil, fmt.Errorf("read exemptions: %w", err)
	}
	var s Store
	if err := json.Unmarshal(content, &s); err != nil {
		return nil, fmt.Errorf("parse exemptions %s: %w", path, err)
	}
	return &s, nil
}

// Save 原子写入豁免文件。
func (s *Store) Save(path string) error {
	content, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return fmt.Errorf("write exemptions: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit exemptions: %w", err)
	}
	return nil
}

func (s *Store) authorized(actor string) bool {
	for _, a := range s.Approvers {
		if a == actor {
			return true
		}
	}
	return false
}

// audit 追加一条审计记录；审计失败不影响已做出的决定，但会返回错误。
func (s *Store) audit(auditPath string, rec auditRecord) error {
	if auditPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// Register 登记豁免；越权或定义非法将被拒绝并记录审计。
func (s *Store) Register(e Exemption, actor string, auditPath string) error {
	rec := auditRecord{Time: time.Now().UTC(), Actor: actor, Action: "register", ExemptionID: e.ID}
	deny := func(reason string) error {
		rec.Decision = "denied"
		rec.Reason = reason
		_ = s.audit(auditPath, rec)
		return fmt.Errorf("register exemption denied: %s", reason)
	}
	if !s.authorized(actor) {
		return deny(fmt.Sprintf("actor %q is not an approver", actor))
	}
	if e.ID == "" || e.CheckID == "" || e.Ref.Kind == "" || e.Ref.Name == "" {
		return deny("id, checkId, ref.kind and ref.name are required")
	}
	if e.ExpiresAt.IsZero() {
		return deny("expiresAt is required")
	}
	for _, existing := range s.Exemptions {
		if existing.ID == e.ID {
			return deny(fmt.Sprintf("duplicate exemption id %q", e.ID))
		}
	}
	e.CreatedBy = actor
	s.Exemptions = append(s.Exemptions, e)
	rec.Decision = "allowed"
	return s.audit(auditPath, rec)
}

// Revoke 撤销豁免；越权或豁免不存在将被拒绝并记录审计。
func (s *Store) Revoke(id string, actor string, auditPath string) error {
	rec := auditRecord{Time: time.Now().UTC(), Actor: actor, Action: "revoke", ExemptionID: id}
	deny := func(reason string) error {
		rec.Decision = "denied"
		rec.Reason = reason
		_ = s.audit(auditPath, rec)
		return fmt.Errorf("revoke exemption denied: %s", reason)
	}
	if !s.authorized(actor) {
		return deny(fmt.Sprintf("actor %q is not an approver", actor))
	}
	for i := range s.Exemptions {
		if s.Exemptions[i].ID == id {
			if s.Exemptions[i].Revoked {
				return deny(fmt.Sprintf("exemption %q already revoked", id))
			}
			s.Exemptions[i].Revoked = true
			rec.Decision = "allowed"
			return s.audit(auditPath, rec)
		}
	}
	return deny(fmt.Sprintf("exemption %q not found", id))
}

// Active 返回当前生效（未撤销、未到期）的豁免，按 ID 排序保证确定性。
func (s *Store) Active(now time.Time) []Exemption {
	var out []Exemption
	for _, e := range s.Exemptions {
		if e.Revoked || !now.Before(e.ExpiresAt) {
			continue
		}
		out = append(out, e)
	}
	for i := 0; i+1 < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].ID < out[i].ID {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
