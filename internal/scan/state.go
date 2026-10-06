package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/finding"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
)

// stateFile is the per-baseline review stream, committed atomically.
//
//   - Interruption recovery: UnitFP lists every fully evaluated unit together
//     with the object fingerprint it was evaluated against. Resuming skips
//     exactly those units, so they never run twice; a unit that never finished
//     is absent, so it cannot leave a half conclusion.
//   - Incremental review across snapshot updates: units whose object is gone
//     are dropped (their findings reclaimed); units whose fingerprint changed
//     are re-evaluated; unchanged units are reused.
//
// State is keyed by baseline version: switching baselines never mutates the
// historical review of another baseline.
type stateFile struct {
	Baseline   string            `json:"baseline"`
	SnapshotID string            `json:"snapshot_id"`
	UnitFP     map[string]string `json:"unit_fp"`
	// UnitEx records the active-exemption signature per evaluated unit, so an
	// expiry/revocation forces re-evaluation even when the object is unchanged.
	UnitEx   map[string]string  `json:"unit_ex,omitempty"`
	Findings []*finding.Finding `json:"findings"`
}

type stateStore struct {
	dir string
}

func newStateStore(dir string) *stateStore { return &stateStore{dir: dir} }

func (s *stateStore) path(baselineVersion string) string {
	return filepath.Join(s.dir, "review-"+safeName(baselineVersion)+".json")
}

func safeName(v string) string {
	out := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// load returns the review state for a baseline, or an empty one. If the state
// was produced against a different snapshot, the caller decides (full scan
// starts over; incremental reuses matching units).
func (s *stateStore) load(baselineVersion string) (*stateFile, error) {
	b, err := os.ReadFile(s.path(baselineVersion))
	if os.IsNotExist(err) {
		return &stateFile{Baseline: baselineVersion, UnitFP: map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse scan state: %w", err)
	}
	if st.Baseline != baselineVersion {
		return nil, fmt.Errorf("scan state baseline mismatch: have %q want %q", st.Baseline, baselineVersion)
	}
	if st.UnitFP == nil {
		st.UnitFP = map[string]string{}
	}
	if st.UnitEx == nil {
		st.UnitEx = map[string]string{}
	}
	return &st, nil
}

// commit writes state atomically via temp-file + rename.
func (s *stateStore) commit(st *stateFile) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".review-*")
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
	return os.Rename(tmpName, s.path(st.Baseline))
}

// unitKey renders one evaluation unit: a check applied to an object.
func unitKey(checkID string, k object.Key) string {
	return checkID + "|" + k.String()
}
