package server

import (
	"crypto/ed25519"
	"fmt"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
)

// Finding an identity's own rotation keys again.
//
// A rotation must carry the key the PREVIOUS event committed to. That key is
// not stored anywhere — only its digest is, in the event — so it has to be
// derived again from the root seed at the index it came from.
//
// That was the whole of the defect this exists to fix. Pairing derived a key,
// used it, cleared the seed from memory and recorded the resulting identifier,
// but never recorded WHERE the key came from. So the identity existed, worked,
// and could never rotate: the one key a rotation had to include was a
// derivation nobody could repeat. An organisation founded that way could not
// take on a co-owner, change hands, or replace a compromised key — permanently,
// and with no error until somebody tried.

// rotationKeys are the two public halves a rotation needs.
type rotationKeys struct {
	// Current is the key the previous event committed to. It leads the new key
	// set, because without it no verifier accepts the rotation at all.
	Current string
	// Next is what this rotation commits to in turn. An event that commits to
	// nothing can never be rotated from, so this is not optional.
	Next string
}

// ownRotationKeys derives the keys this identity would rotate with.
//
// Generation is how far along its derivation branch the identity currently is:
// at generation g, the current key is at key-index g and the successor already
// committed to is at g+1. Rotating makes that successor current and commits to
// g+2.
func (s *CoreServer) ownRotationKeys() (*rotationKeys, error) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return nil, fmt.Errorf("this agent has no identity to rotate")
	}

	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("no key material to derive from: %w", err)
	}

	// The successor committed to at inception becomes the current key of the
	// rotation, and the one after it becomes the new commitment.
	currentSeed, err := backup.DerivePairwiseSeed(
		rootSeed, identity.DerivationIndex, identity.KeyGeneration+1)
	if err != nil {
		return nil, fmt.Errorf("could not derive the committed key: %w", err)
	}
	nextSeed, err := backup.DerivePairwiseSeed(
		rootSeed, identity.DerivationIndex, identity.KeyGeneration+2)
	if err != nil {
		return nil, fmt.Errorf("could not derive its successor: %w", err)
	}

	current := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(currentSeed).Public().(ed25519.PublicKey))
	next := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey))

	// Checked against what the identity actually committed to, rather than
	// assumed. A derived key that does not match the recorded digest means the
	// index or the generation is wrong, and rotating on it would produce an
	// event every verifier refuses — after the ceremony that built it had
	// already collected everybody's signatures.
	if digest := identity.NextKeyDigest; digest != "" {
		if got := iacrypto.Blake3QB64Must([]byte(current)); got != digest {
			return nil, fmt.Errorf(
				"the derived key does not match what this identity committed to — "+
					"its recorded derivation (index %d, generation %d) is wrong, and a rotation "+
					"built on it would be refused",
				identity.DerivationIndex, identity.KeyGeneration)
		}
	}

	return &rotationKeys{Current: current, Next: next}, nil
}

// advanceKeyGeneration records that a rotation happened, so the next one
// derives from the right place.
//
// Called after the rotation is accepted, never before. Advancing first and
// failing would leave the identity believing it had moved on while its log said
// otherwise — and every future rotation would derive a key the events do not
// commit to.
func (s *CoreServer) advanceKeyGeneration(newPublicKey, newNextKeyDigest string) error {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return fmt.Errorf("no identity to advance")
	}
	identity.KeyGeneration++
	identity.PublicKey = newPublicKey
	identity.NextKeyDigest = newNextKeyDigest
	identity.EventCount++
	return s.DataStore.SaveIdentity(*identity)
}
