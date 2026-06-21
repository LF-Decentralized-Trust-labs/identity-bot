package backup

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	SnapshotFull  = "full"
	SnapshotDelta = "delta"
)

// DeltaState tracks section digests and incremental backup chain metadata.
type DeltaState struct {
	SectionDigests   map[string]string `json:"section_digests"`
	LastFullAt       string            `json:"last_full_at"`
	ChainDigestQB64  string            `json:"chain_digest_blake3_qb64"`
	DeltaChainLen    int               `json:"delta_chain_len"`
	LastCompactionAt string            `json:"last_compaction_at,omitempty"`
}

var tier1SectionNames = map[string]bool{
	"identity_state":       true,
	"kel_events":           true,
	"sqlite_identity_db":   true,
	"login_relationships":  true,
}

func isTier2Or3Section(name string) bool {
	if tier1SectionNames[name] {
		return false
	}
	return strings.HasPrefix(name, "log_") ||
		name == "contacts" ||
		name == "credentials" ||
		name == "settings" ||
		name == "pending_requests" ||
		name == "ai_memory_db" ||
		name == "sandbox_index"
}

// ComputeDeltaStateDigest returns Blake3-256 qb64 of canonical delta state (excluding chain digest).
func ComputeDeltaStateDigest(ds DeltaState) (string, error) {
	payload, err := deltaStateCanonicalJSON(ds)
	if err != nil {
		return "", err
	}
	return DigestSection(payload)
}

func deltaStateCanonicalJSON(ds DeltaState) ([]byte, error) {
	type canonical struct {
		SectionDigests   map[string]string `json:"section_digests"`
		LastFullAt       string            `json:"last_full_at"`
		DeltaChainLen    int               `json:"delta_chain_len"`
		LastCompactionAt string            `json:"last_compaction_at,omitempty"`
	}
	keys := make([]string, 0, len(ds.SectionDigests))
	for k := range ds.SectionDigests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]string, len(keys))
	for _, k := range keys {
		ordered[k] = ds.SectionDigests[k]
	}
	return json.Marshal(canonical{
		SectionDigests:   ordered,
		LastFullAt:       ds.LastFullAt,
		DeltaChainLen:    ds.DeltaChainLen,
		LastCompactionAt: ds.LastCompactionAt,
	})
}

// VerifyChain checks that the pinned chain digest matches recomputed Blake3-256 state.
func (ds *DeltaState) VerifyChain() error {
	if ds == nil {
		return fmt.Errorf("nil delta state")
	}
	computed, err := ComputeDeltaStateDigest(*ds)
	if err != nil {
		return err
	}
	if ds.ChainDigestQB64 == "" {
		return fmt.Errorf("missing chain digest")
	}
	if computed != ds.ChainDigestQB64 {
		return fmt.Errorf("delta chain digest mismatch")
	}
	return nil
}

// DecideSnapshotType picks full vs delta based on schedule and chain health.
func DecideSnapshotType(ds DeltaState, reason string, forceFull bool) (string, bool) {
	if forceFull {
		return SnapshotFull, false
	}
	now := time.Now().UTC()

	if ds.ChainDigestQB64 != "" {
		if err := ds.VerifyChain(); err != nil {
			return SnapshotFull, true
		}
	}

	if ds.LastCompactionAt != "" {
		if t, err := time.Parse(time.RFC3339, ds.LastCompactionAt); err == nil {
			if now.Sub(t) >= 30*24*time.Hour {
				return SnapshotFull, false
			}
		}
	} else if ds.LastFullAt != "" {
		// First compaction baseline from first full snapshot.
		if t, err := time.Parse(time.RFC3339, ds.LastFullAt); err == nil {
			if now.Sub(t) >= 30*24*time.Hour {
				return SnapshotFull, false
			}
		}
	}

	if ds.LastFullAt == "" {
		return SnapshotFull, false
	}
	if t, err := time.Parse(time.RFC3339, ds.LastFullAt); err == nil {
		if now.Sub(t) >= 7*24*time.Hour {
			return SnapshotFull, false
		}
	}

	switch reason {
	case "daily_timer", string(EventKeyRotation), string(EventCredential),
		string(EventContactVerified), string(EventProfileChange), string(EventManual), "":
		if ds.LastFullAt == "" {
			return SnapshotFull, false
		}
		return SnapshotDelta, false
	default:
		if strings.HasPrefix(reason, "event_") {
			return SnapshotDelta, false
		}
		return SnapshotFull, false
	}
}

// FilterDeltaBundle returns tier1 sections plus changed tier2/3 sections for delta archives.
func FilterDeltaBundle(full *PayloadBundle, prev *DeltaState, tiers []string) *PayloadBundle {
	if full == nil {
		return &PayloadBundle{Sections: map[string][]byte{}, Ordered: []PayloadSection{}}
	}
	includeTier23 := tierSetIncludes23(tiers)
	out := &PayloadBundle{Sections: map[string][]byte{}, Ordered: []PayloadSection{}}
	prevDigests := map[string]string{}
	if prev != nil && prev.SectionDigests != nil {
		prevDigests = prev.SectionDigests
	}

	for _, sec := range full.Ordered {
		dig := DigestSectionMust(sec.Data)
		if tier1SectionNames[sec.Name] {
			out.addSection(sec.Name, sec.Data)
			continue
		}
		if !includeTier23 || !isTier2Or3Section(sec.Name) {
			continue
		}
		if prevDigests[sec.Name] != dig {
			out.addSection(sec.Name, sec.Data)
		}
	}
	return out
}

func tierSetIncludes23(tiers []string) bool {
	for _, t := range tiers {
		if t == TierImportant || t == TierFull {
			return true
		}
	}
	return false
}

func (b *PayloadBundle) addSection(name string, data []byte) {
	b.Sections[name] = data
	b.Ordered = append(b.Ordered, PayloadSection{Name: name, Data: data})
}

// UpdateDeltaStateAfterBackup advances chain digests from the full collected bundle.
func UpdateDeltaStateAfterBackup(ds *DeltaState, full *PayloadBundle, snapshotType string, compaction bool) error {
	if ds == nil {
		return fmt.Errorf("nil delta state")
	}
	if ds.SectionDigests == nil {
		ds.SectionDigests = map[string]string{}
	}
	if full != nil {
		for _, sec := range full.Ordered {
			ds.SectionDigests[sec.Name] = DigestSectionMust(sec.Data)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if snapshotType == SnapshotFull {
		ds.LastFullAt = now
		ds.DeltaChainLen = 0
		if compaction || ds.LastCompactionAt == "" {
			ds.LastCompactionAt = now
		}
	} else {
		ds.DeltaChainLen++
	}
	dig, err := ComputeDeltaStateDigest(*ds)
	if err != nil {
		return err
	}
	ds.ChainDigestQB64 = dig
	return nil
}

// ResetDeltaState returns a zeroed chain (used on mismatch fail-safe).
func ResetDeltaState() DeltaState {
	return DeltaState{SectionDigests: map[string]string{}}
}