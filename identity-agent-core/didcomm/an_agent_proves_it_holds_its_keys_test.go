package didcomm

import (
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
)

// A log whose last keyset anchor is ks's: the shape CheckKeysBelongTo reads
// (the caller has already verified the log).
func logAnchoring(t *testing.T, ks *KeySet) []map[string]interface{} {
	t.Helper()
	did, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	_ = did
	dsa, _ := ks.DsaPub.MarshalBinary()
	kem, _ := ks.KemPub.MarshalBinary()
	anchor, err := iacrypto.KeySetAnchor(ks.XPub[:], kem, ks.EdPub, dsa)
	if err != nil {
		t.Fatal(err)
	}
	return []map[string]interface{}{
		{"t": "icp", "i": ks.AID, "a": []interface{}{anchor}},
	}
}

const (
	proofAID    = "EAgentIdentifier"
	proofOrigin = "https://agent.example:443"
	proofAsk    = "a-fresh-random-challenge-0001"
)

func aProofKeySet(t *testing.T) *KeySet {
	t.Helper()
	ks, err := GenerateKeySet(proofAID)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestAFreshAnswerFromTheKeysInForceVerifies(t *testing.T) {
	ks := aProofKeySet(t)
	now := time.Now()
	p, err := ProveKeysInForce(ks, "", proofOrigin, proofAsk, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckKeyProof(p, proofAID, proofOrigin, proofAsk, logAnchoring(t, ks), "", now); err != nil {
		t.Fatalf("a fresh answer from the keys in force was refused: %v", err)
	}
}

// The address that relays the public log and holds no keys: it has to offer
// keys of its own, and they are not the ones the log commits to.
func TestAnAddressThatRelaysTheLogButCannotSignIsRefused(t *testing.T) {
	real := aProofKeySet(t)
	log := logAnchoring(t, real) // what the proxy relays, correctly
	impostor := aProofKeySet(t)  // what it holds
	now := time.Now()
	p, err := ProveKeysInForce(impostor, "", proofOrigin, proofAsk, now)
	if err != nil {
		t.Fatal(err)
	}
	err = CheckKeyProof(p, proofAID, proofOrigin, proofAsk, log, "", now)
	if err == nil || !strings.Contains(err.Error(), "committed to") {
		t.Fatalf("keys the log does not commit to were accepted, or refused for another reason: %v", err)
	}

	// And keys copied from the log with a signature made by other keys.
	p, _ = ProveKeysInForce(real, "", proofOrigin, proofAsk, now)
	forged, _ := ProveKeysInForce(impostor, "", proofOrigin, proofAsk, now)
	p.EdSig, p.DsaSig = forged.EdSig, forged.DsaSig
	if err := CheckKeyProof(p, proofAID, proofOrigin, proofAsk, log, "", now); err == nil {
		t.Fatal("the right keys with another key's signature were accepted")
	}
}

func TestAReplayedAnswerIsRefused(t *testing.T) {
	ks := aProofKeySet(t)
	log := logAnchoring(t, ks)
	now := time.Now()
	recorded, _ := ProveKeysInForce(ks, "", proofOrigin, "the-challenge-of-last-time-1", now)

	// Answered to another challenge.
	err := CheckKeyProof(recorded, proofAID, proofOrigin, proofAsk, log, "", now)
	if err == nil || !strings.Contains(err.Error(), "different challenge") {
		t.Fatalf("an answer to an earlier challenge was accepted: %v", err)
	}
	// Relabelled with the new challenge: the signature no longer covers it.
	recorded.Challenge = proofAsk
	if err := CheckKeyProof(recorded, proofAID, proofOrigin, proofAsk, log, "", now); err == nil {
		t.Fatal("a recorded answer with the new challenge written over it was accepted")
	}
	// Even to the same challenge, a long-old answer is refused.
	old, _ := ProveKeysInForce(ks, "", proofOrigin, proofAsk, now.Add(-time.Hour))
	if err := CheckKeyProof(old, proofAID, proofOrigin, proofAsk, log, "", now); err == nil {
		t.Fatal("an hour-old answer was accepted")
	}
}

// A relay that forwards everything gets a genuine answer, for the address the
// agent knows; it is refused because that is not the address that was dialled.
func TestAnAnswerForAnotherAddressIsRefused(t *testing.T) {
	ks := aProofKeySet(t)
	now := time.Now()
	p, _ := ProveKeysInForce(ks, "", "https://real.example:443", proofAsk, now)
	err := CheckKeyProof(p, proofAID, "https://proxy.example:443", proofAsk, logAnchoring(t, ks), "", now)
	if err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("an answer for another address was accepted: %v", err)
	}
}

// Keys the identifier has since replaced no longer answer for it.
func TestKeysTheLogHasReplacedAreRefused(t *testing.T) {
	old, now := aProofKeySet(t), time.Now()
	newer := aProofKeySet(t)
	log := append(logAnchoring(t, old), logAnchoring(t, newer)...)
	p, _ := ProveKeysInForce(old, "", proofOrigin, proofAsk, now)
	if err := CheckKeyProof(p, proofAID, proofOrigin, proofAsk, log, "", now); err == nil {
		t.Fatal("keys the log replaced were accepted")
	}
	p, _ = ProveKeysInForce(newer, "", proofOrigin, proofAsk, now)
	if err := CheckKeyProof(p, proofAID, proofOrigin, proofAsk, log, "", now); err != nil {
		t.Fatalf("the keys now in force were refused: %v", err)
	}
}

func TestAnAnswerForAnotherIdentifierIsRefused(t *testing.T) {
	ks, now := aProofKeySet(t), time.Now()
	p, _ := ProveKeysInForce(ks, "", proofOrigin, proofAsk, now)
	if err := CheckKeyProof(p, "EOther", proofOrigin, proofAsk, logAnchoring(t, ks), "", now); err == nil {
		t.Fatal("an answer for one identifier was accepted for another")
	}
}

func TestALogOfAnotherIdentifierIsRefused(t *testing.T) {
	ks := aProofKeySet(t)
	now := time.Now()
	p, err := ProveKeysInForce(ks, "", proofOrigin, proofAsk, now)
	if err != nil {
		t.Fatal(err)
	}
	log := logAnchoring(t, ks)
	log[0]["i"] = "EAnotherIdentifier"
	err = CheckKeyProof(p, proofAID, proofOrigin, proofAsk, log, "", now)
	if err == nil || !strings.Contains(err.Error(), "not the log of") {
		t.Fatalf("a log of another identifier must be refused, got %v", err)
	}
	if err := CheckKeyProof(p, proofAID, proofOrigin, proofAsk, nil, "", now); err == nil {
		t.Fatal("an empty log must be refused")
	}
}
