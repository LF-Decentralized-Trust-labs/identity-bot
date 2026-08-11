package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/backup"
	"identity-agent-core/didcomm"
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

	var rec messagingKeyRecord
	if data, rerr := os.ReadFile(s.messagingKeyPath()); rerr == nil &&
		json.Unmarshal(data, &rec) == nil && rec.Index > 0 {
		ks, derr := s.keysAtIndex(rootSeed, aid, rec.Index)
		return ks, rec.Index, derr
	}

	if s.DataStore == nil {
		return nil, 0, fmt.Errorf("no store to allocate a branch for messaging keys")
	}
	idx, aerr := s.DataStore.AllocateNextRelationshipIndex(messagingKeysPurpose)
	if aerr != nil {
		return nil, 0, fmt.Errorf("could not allocate a branch for messaging keys: %w", aerr)
	}
	ks, derr := s.keysAtIndex(rootSeed, aid, idx)
	if derr != nil {
		return nil, 0, derr
	}
	if werr := s.recordMessagingKeyIndex(aid, idx); werr != nil {
		return nil, 0, werr
	}
	return ks, idx, nil
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
	if err := os.WriteFile(s.messagingKeyPath(), data, 0600); err != nil {
		return fmt.Errorf("could not record which branch the messaging keys came from: %w", err)
	}
	return nil
}
