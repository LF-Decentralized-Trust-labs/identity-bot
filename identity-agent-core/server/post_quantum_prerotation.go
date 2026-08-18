package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// The branch the post-quantum pre-rotation key is derived from.
//
// Fixed rather than allocated. That is what makes the recovery phrase
// sufficient on its own: an owner rebuilding on a new device regenerates this
// key from the phrase with no file to restore and no record to find. An
// allocated branch would have to be written down somewhere, and anything that
// has to be written down is something a restore can lose.
//
// It takes the base of its own pool rather than branch (0, 1), which was the
// first choice and was wrong. Zero is the value an identity's DerivationIndex
// and KeyGeneration hold when nothing set them, so ownRotationKeys derives the
// committed ROTATION key at exactly (0, 1) too. Both would then be the same 32
// bytes — one secret behind an Ed25519 rotation key and the post-quantum
// pre-rotation key, committed to in the same event, so obtaining either would
// yield the whole pre-rotation set. A digest check happens to refuse it today,
// which makes this a hazard rather than a live flaw, and not one worth leaving
// for a future caller to walk into.
const (
	postQuantumPreRotationContact = 7000001
	postQuantumPreRotationKey     = 0
)

// postQuantumCommitmentRecord is what was committed, kept so a later rotation
// can check it still reproduces before publishing anything.
type postQuantumCommitmentRecord struct {
	// Digest is the commitment written into the founding event's `n`.
	Digest string `json:"digest"`
	// Verkey is the encoded key the digest was taken over.
	Verkey string `json:"verkey"`
	// Code records which CESR code the encoding assumed. Written down because
	// it is the thing most likely to be wrong: if the specification assigns a
	// different code than the one proposed, a rotation must be able to see that
	// this commitment was made under the old assumption rather than discovering
	// it as an unexplained mismatch.
	Code string `json:"code"`
}

func (s *CoreServer) postQuantumCommitmentPath() string {
	return filepath.Join(s.DataDir, "post_quantum_commitment.json")
}

// postQuantumPreRotation builds the pre-rotation commitments for a new identity.
//
// Returns the full digest set for `n` — the classical commitment first, so the
// event keeps the shape every existing reader expects, with the post-quantum
// one added alongside it.
//
// Returns nil on any failure, which leaves the caller founding the identity
// with its single classical commitment exactly as before. That is the right
// trade: what is lost is the option to rotate to a post-quantum key later, and
// refusing to found an identity at all would be a much larger harm than losing
// a future option.
func (s *CoreServer) postQuantumPreRotation(nextPublicKey string) ([]string, *iacrypto.PostQuantumNextKey) {
	if nextPublicKey == "" {
		return nil, nil
	}

	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		log.Printf("[identity-agent-core] INCEPTION: no root seed, so this identity commits "+
			"to no post-quantum key and cannot rotate to one later: %v", err)
		return nil, nil
	}

	seed, err := backup.DerivePairwiseSeed(rootSeed, postQuantumPreRotationContact, postQuantumPreRotationKey)
	if err != nil {
		log.Printf("[identity-agent-core] INCEPTION: could not derive the post-quantum "+
			"pre-rotation seed: %v", err)
		return nil, nil
	}

	pq, err := iacrypto.PostQuantumNextKeyFromSeed(seed)
	if err != nil {
		log.Printf("[identity-agent-core] INCEPTION: could not derive the post-quantum "+
			"pre-rotation key: %v", err)
		return nil, nil
	}

	// The classical commitment has to be computed here too, because passing a
	// digest set replaces the single one the engine would otherwise derive from
	// the next public key. Getting this wrong is silent — the event still looks
	// right — so it is computed the same way a validator recomputes it, over
	// the key's qb64 text.
	classical, err := iacrypto.NextKeyDigest(nextPublicKey)
	if err != nil {
		log.Printf("[identity-agent-core] INCEPTION: could not commit to the classical "+
			"next key, so no post-quantum commitment is made either: %v", err)
		return nil, nil
	}

	return []string{classical, pq.Digest}, &pq
}

// recordPostQuantumCommitment writes down what the identity committed to.
//
// The key itself is not stored. It derives from the root seed at a fixed
// branch, so the phrase reproduces it and a copy on disk would be one more
// secret to protect for no gain. What is worth keeping is the commitment: a
// rotation can then check it reproduces before publishing, rather than
// discovering at the worst moment that it does not.
func (s *CoreServer) recordPostQuantumCommitment(pq *iacrypto.PostQuantumNextKey) error {
	if pq == nil {
		return nil
	}
	rec := postQuantumCommitmentRecord{
		Digest: pq.Digest,
		Verkey: pq.Verkey,
		Code:   iacrypto.ProposedMLDSA65Verkey,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("could not encode the post-quantum commitment: %w", err)
	}
	if err := os.WriteFile(s.postQuantumCommitmentPath(), data, 0600); err != nil {
		return fmt.Errorf("could not record the post-quantum commitment: %w", err)
	}
	return nil
}
