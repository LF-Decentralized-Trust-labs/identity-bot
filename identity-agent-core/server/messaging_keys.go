package server

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"

	"identity-agent-core/backup"
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/atomicfile"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/secureenclave"
)

// Where an identity's messaging keys come from.
//
// They used to be drawn from the system random source, which put them in
// exactly one place: this device. Restoring from the recovery phrase brought
// the KERI identity back and left the messaging keys behind — and since the
// identifier commits to them, the restored identity advertised keys nobody held
// the private half of. Able to prove who it was, unable ever to be sent
// anything, permanently, because no later event can withdraw what an inception
// committed to.
//
// Derived from the same root seed as every other key the agent holds, at its
// own branch, so the recovery phrase restores an identity that still works
// rather than one that only looks intact.

const messagingKeysPurpose = "messaging-keys"

type messagingKeyRecord struct {
	// AID the keys belong to, recorded so a mismatch is visible rather than
	// silently producing the wrong keys for the wrong identity.
	AID string `json:"aid"`
	// Index is the branch of the root seed. This is the whole of what has to
	// survive: with the recovery phrase and this number, the keys come back.
	Index int `json:"index"`
}

var messagingKeyMu sync.Mutex

func (s *CoreServer) messagingKeyPath() string {
	return filepath.Join(s.DataDir, "messaging_keys.json")
}

// deriveMessagingKeys makes an identity's messaging keyset from the root seed,
// allocating a branch for it on first use.
//
// aid may be empty at inception, when the identifier does not exist yet — the
// keys have to be made before it, because it is derived from an event that
// commits to them. The record is completed once the identifier is known.
func (s *CoreServer) deriveMessagingKeys(aid string) (*didcomm.KeySet, int, error) {
	messagingKeyMu.Lock()
	defer messagingKeyMu.Unlock()

	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, 0, fmt.Errorf("no key material to derive messaging keys from: %w", err)
	}

	// A record that cannot be read is refused, never taken for none: a new
	// branch here would be written over the one record a restore needs to
	// bring these keys back (readKeptRecord).
	var rec messagingKeyRecord
	found, rerr := readKeptRecord(s.messagingKeyPath(), "the record of which branch the messaging keys came from",
		"this Identity Agent cannot prepare or file its messaging keys", coretypes.ErrKeysUnavailable, &rec)
	if rerr != nil {
		return nil, 0, rerr
	}
	// An identity founded before the fixed branch keeps the branch its
	// record names until its keyset is replaced (ADR-061 section 8).
	if found && rec.Index > 0 {
		ks, derr := s.keysAtIndex(rootSeed, aid, rec.Index)
		return ks, rec.Index, derr
	}

	// Every other identity's messaging keys come from the fixed branch, so
	// the phrase alone finds them: generation 0 of m/44'/0'/0'/7000002'/g'.
	// Index 0 in the record means this branch; no allocated branch is 0.
	ks, err := fixedBranchMessagingKeys(rootSeed, aid, 0)
	if err != nil {
		return nil, 0, err
	}
	if werr := s.recordMessagingKeyIndex(aid, 0); werr != nil {
		return nil, 0, werr
	}
	return ks, 0, nil
}

// fixedBranchMessagingKeys is the messaging keyset of generation g on the fixed
// branch, the one an app derives for an identity whose key it holds.
func fixedBranchMessagingKeys(rootSeed []byte, aid string, g int) (*didcomm.KeySet, error) {
	seed, err := backup.DerivePairwiseSeed(rootSeed, backup.MessagingBranch, g)
	if err != nil {
		return nil, fmt.Errorf("could not derive the messaging-key seed: %w", err)
	}
	return didcomm.DeriveKeySet(aid, seed)
}

func (s *CoreServer) keysAtIndex(rootSeed []byte, aid string, idx int) (*didcomm.KeySet, error) {
	seed, err := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if err != nil {
		return nil, fmt.Errorf("could not derive the messaging-key seed: %w", err)
	}
	return didcomm.DeriveKeySet(aid, seed)
}

// recordMessagingKeyIndex writes down which branch the keys came from.
//
// Without it the keys are still derivable in principle and unfindable in
// practice, which is the same as lost.
func (s *CoreServer) recordMessagingKeyIndex(aid string, idx int) error {
	data, _ := json.Marshal(messagingKeyRecord{AID: aid, Index: idx})
	if err := atomicfile.Write(s.messagingKeyPath(), data, 0600); err != nil {
		return fmt.Errorf("could not record which branch the messaging keys came from: %w", err)
	}
	return nil
}
