package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"identity-agent-core/witness"
	"path/filepath"
	"sync"

	"identity-agent-core/atomicfile"
	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// The key this agent witnesses with.
//
// A receipt exists so that a third party can check it. Until now the agent
// produced one by hashing the receipt it had just written and calling the
// result a signature — a value derived entirely from public data, which anybody
// holding the event could compute and nobody could distinguish from a genuine
// one. The witness was doing real work (refusing gaps, refusing a second event
// at a sequence number it had already seen) and then attesting to none of it.
//
// It cannot sign as the agent's own identity: on a computer that identity's key
// is derived on the owner's device from their recovery phrase and never reaches
// the agent, so the agent has nothing to sign with. Reaching for it here is what
// produced the stub in the first place.
//
// KERI's own convention answers both halves. A witness is named by a
// NON-TRANSFERABLE identifier, which is its verifying key carrying a prefix. So
// the agent can hold this key itself, and a verifier needs nothing but the
// identifier already written in the key event to check the signature — no
// fetch, no address, nothing that can answer wrongly.
//
// Derived from the same root seed as every other key the agent holds, at its
// own reserved branch, so restoring from the recovery phrase restores the
// ability to witness rather than silently producing a different witness.

const witnessSigningPurpose = "witnessing"

type witnessKeyRecord struct {
	// AID is the non-transferable identifier — the public key with its prefix.
	AID string `json:"aid"`
	// Index is the branch of the root seed this key came from. Recorded so the
	// same key is derived again rather than a new one being allocated, which
	// would silently retire every receipt already issued.
	Index int `json:"index"`
}

var witnessKeyMu sync.Mutex

func (s *CoreServer) witnessKeyPath() string {
	return filepath.Join(s.DataDir, "witness_signing.json")
}

// witnessSigningKey returns the seed and identifier this agent witnesses with,
// allocating them on first use.
func (s *CoreServer) witnessSigningKey() (seed []byte, aid string, err error) {
	witnessKeyMu.Lock()
	defer witnessKeyMu.Unlock()

	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, "", fmt.Errorf("no key material to witness with: %w", err)
	}

	// A record that cannot be read is refused, never taken for none: a new
	// key here would be written over it and retire every receipt already
	// issued (readKeptRecord).
	var rec witnessKeyRecord
	found, rerr := readKeptRecord(s.witnessKeyPath(), "the record of this Identity Agent's witnessing key",
		"this Identity Agent cannot witness", coretypes.ErrKeysUnavailable, &rec)
	if rerr != nil {
		return nil, "", rerr
	}
	if found && rec.AID != "" {
		seed, derr := backup.DerivePairwiseSeed(rootSeed, rec.Index, 0)
		if derr != nil {
			return nil, "", fmt.Errorf("could not derive the witnessing key: %w", derr)
		}
		// Checked rather than assumed. A recorded index that no longer produces
		// the recorded identifier means the seed changed underneath us, and
		// signing anyway would produce receipts that verify against nothing.
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if got := iacrypto.NonTransferableAIDQB64(pub); got != rec.AID {
			return nil, "", fmt.Errorf(
				"the recorded witnessing key no longer derives from this agent's seed, so its "+
					"receipts would verify against nothing (recorded %s, derived %s)", rec.AID, got)
		}
		return seed, rec.AID, nil
	}

	if s.DataStore == nil {
		return nil, "", fmt.Errorf("no store to allocate a witnessing key from")
	}
	idx, aerr := s.DataStore.AllocateNextRelationshipIndex(witnessSigningPurpose)
	if aerr != nil {
		return nil, "", fmt.Errorf("could not allocate a branch for the witnessing key: %w", aerr)
	}
	seed, derr := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if derr != nil {
		return nil, "", fmt.Errorf("could not derive the witnessing key: %w", derr)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	aid = iacrypto.NonTransferableAIDQB64(pub)
	if aid == "" {
		return nil, "", fmt.Errorf("could not encode the witnessing identifier")
	}

	data, _ := json.Marshal(witnessKeyRecord{AID: aid, Index: idx})
	if werr := atomicfile.Write(s.witnessKeyPath(), data, 0600); werr != nil {
		return nil, "", fmt.Errorf("could not record the witnessing key: %w", werr)
	}
	return seed, aid, nil
}

// signWitnessReceipt signs a short statement as this agent's witnessing
// identity: a tip statement or an answer to a witness request. It does not sign
// receipts of events; signWitnessEventReceipt does, in the form keripy reads.
func (s *CoreServer) signWitnessReceipt(said string) (witnessAID, cesrSig string, err error) {
	if said == "" {
		return "", "", fmt.Errorf("there is no event to receipt")
	}
	seed, aid, err := s.witnessSigningKey()
	if err != nil {
		return "", "", err
	}
	sig, err := login.SignString(said, seed)
	if err != nil {
		return "", "", fmt.Errorf("could not sign the receipt: %w", err)
	}
	return aid, sig, nil
}

// signWitnessEventReceipt receipts a key event as this agent's witnessing
// identity, in the form keripy's Hab.witness makes: an indexed signature over
// the serialised event, indexed by this witness's place in the controller's
// witness list. It refuses when this witness is not in the list, as keripy does.
func (s *CoreServer) signWitnessEventReceipt(rawEvent []byte, designated []string) (witnessAID, cesrSig string, err error) {
	seed, aid, err := s.witnessSigningKey()
	if err != nil {
		return "", "", err
	}
	at := drivers.WitnessPosition(designated, aid)
	if at < 0 {
		return "", "", witness.ErrNotDesignated
	}
	sig, err := drivers.SignEventReceipt(rawEvent, seed, at)
	if err != nil {
		return "", "", err
	}
	return aid, sig, nil
}
