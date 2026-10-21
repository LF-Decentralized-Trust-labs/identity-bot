package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
	"identity-agent-core/tunnel"
)

// tunnelNameOwner is the identity that owns this agent's Grape ID tunnel name.
//
// The hub binds a name to the key that claimed it and checks every later
// request — reconnecting after a restart, giving the name up — against that
// key. So the identity is minted once, in a pool of its own, and remembered:
// presenting a different one at the next start would find the name owned by
// somebody else and leave this agent without its address. A pairwise identity
// rather than the root, for the same reason a relay enrolment is one: the hub
// needs proof of who holds the name, not this agent's own identifier.
func (s *CoreServer) tunnelNameOwner(domain string) (*tunnel.NameOwner, error) {
	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("this agent has no identity yet to own a tunnel name with")
	}
	rec, found, lerr := loadRecordedIdentity(s.DataDir, tunnelNameOwnerFileName)
	if lerr != nil {
		log.Printf("[tunnel] the recorded tunnel name owner is unreadable (%v) — minting a new one, "+
			"which cannot reconnect to a name the old one claimed", lerr)
		found = false
	}
	var seed []byte
	if found {
		if seed, err = backup.DerivePairwiseSeed(rootSeed, rec.RelationshipIndex, 0); err != nil {
			return nil, err
		}
		registerPairwiseKey(rec.AID, rec.PublicKey)
		if len(rec.KEL) > 0 {
			registerPairwiseKEL(rec.AID, rec.KEL)
		}
	} else {
		aid, _, minted, idx, merr := s.mintPairwiseIn("tunnel-name", "tunnel-name")
		if merr != nil {
			return nil, fmt.Errorf("mint the identity that owns the tunnel name: %w", merr)
		}
		seed = minted
		rec = &storedRelayEnrollment{BaseURL: domain, AID: aid, RelationshipIndex: idx, PublicKey: rawPublicKeyB64(seed)}
		if kel, ok := getPairwiseKEL(aid); ok {
			rec.KEL = kel
		}
		if serr := saveRecordedIdentity(s.DataDir, tunnelNameOwnerFileName, *rec); serr != nil {
			log.Printf("[tunnel] WARNING: could not record the tunnel name owner, so the next start "+
				"cannot reconnect to this name: %v", serr)
		}
	}
	stream, err := signedInceptionKEL(rec.AID, rec.KEL, seed)
	if err != nil {
		return nil, err
	}
	return &tunnel.NameOwner{
		AID:          rec.AID,
		PublicKeyB64: rec.PublicKey,
		KELCESRB64:   base64.StdEncoding.EncodeToString(stream),
		Sign:         func(canonical []byte) (string, error) { return signEd25519(seed, canonical) },
	}, nil
}

func rawPublicKeyB64(seed []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

// signEd25519 is a plain Ed25519 signature, base64url, in the same encoding the
// public key travels in beside it.
func signEd25519(seed, message []byte) (string, error) {
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("signing key is %d bytes, expected an Ed25519 seed", len(seed))
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), message)), nil
}
