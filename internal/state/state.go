// Package state 维护增量复核与断点恢复所需的持久化状态。
//
// 状态以对象为单位原子提交：每个对象的内容指纹与其全部结论一起落盘，
// 因此中断后不会留下"半个对象"的半成品结论；已提交对象在恢复后直接复用，
// 未提交对象重新求值，最终结果与一次性跑完一致。
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
)

// ObjectState 记录单个对象上次复核时的指纹与原始结论（未套用豁免）。
type ObjectState struct {
	Hash     string          `json:"hash"`
	Findings []model.Finding `json:"findings"`
}

// Store 是扫描状态仓库（增量复核与断点恢复共用一个文件）。
type Store struct {
	BaselineVersion string                 `json:"baselineVersion"`
	Objects         map[string]ObjectState `json:"objects"`
}

// New 返回空仓库。
func New(version string) *Store {
	return &Store{BaselineVersion: version, Objects: map[string]ObjectState{}}
}

// Load 读取状态文件；不存在时返回空仓库。
func Load(path string) (*Store, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(""), nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s Store
	if err := json.Unmarshal(content, &s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Objects == nil {
		s.Objects = map[string]ObjectState{}
	}
	return &s, nil
}

// Save 原子写入状态文件（临时文件 + rename），中断不会留下截断文件。
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
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit state: %w", err)
	}
	return nil
}

// HashObject 计算对象内容的规范化指纹。
func HashObject(obj model.Object) string {
	h := sha256.New()
	// encoding/json 对 map 键排序输出，序列化结果确定。
	enc, _ := json.Marshal(struct {
		Ref    model.ObjectRef `json:"ref"`
		Fields map[string]any  `json:"fields"`
	}{Ref: obj.Ref, Fields: obj.Fields})
	h.Write(enc)
	return hex.EncodeToString(h.Sum(nil))
}
