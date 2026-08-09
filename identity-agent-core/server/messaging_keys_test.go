package server

import (
	"bytes"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/didcomm"
	"identity-agent-core/secureenclave"
)

func sameKeys(a, b *didcomm.KeySet) bool {
	if a == nil || b == nil {
		return false
	}
	ad, _ := a.DID()
	bd, _ := b.DID()
	if ad == nil || bd == nil {
		return false
	}
	return ad.Ed == bd.Ed && ad.Dsa == bd.Dsa && ad.X25519 == bd.X25519 && ad.MlKem == bd.MlKem
}

// The property the recovery phrase is supposed to have.
//
// These keys used to come from the system random source, so they existed on one
// device and nowhere else. Restoring brought the identity back and left the keys
// behind — and because the identifier commits to them, the restored identity
// advertised keys nobody held the private half of: able to prove who it was,
// unable ever to be sent anything, permanently, since no later event can
// withdraw an inception's commitment.
func TestTheSameSeedProducesTheSameMessagingKeys(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i * 3)
	}
	branch, err := backup.DerivePairwiseSeed(seed, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	first, err := didcomm.DeriveKeySet("EIdentity", branch)
	if err != nil {
		t.Fatal(err)
	}
	second, err := didcomm.DeriveKeySet("EIdentity", branch)
	if err != nil {
		t.Fatal(err)
	}
	if !sameKeys(first, second) {
		t.Fatal("the same seed produced different keys, so a restore cannot reproduce them")
	}
}

// And a different seed must not.
func TestADifferentSeedProducesDifferentMessagingKeys(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(i + 1)
	}
	ks1, err := didcomm.DeriveKeySet("EIdentity", a)
	if err != nil {
		t.Fatal(err)
	}
	ks2, err := didcomm.DeriveKeySet("EIdentity", b)
	if err != nil {
		t.Fatal(err)
	}
	if sameKeys(ks1, ks2) {
		t.Fatal("two different seeds produced the same keys")
	}
}

// No derived key may be usable as another. They are separated at the point they
// are made rather than relying on nothing ever mixing them up later.
func TestTheFourKeysAreNotTheSameMaterial(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 5)
	}
	ks, err := didcomm.DeriveKeySet("EIdentity", seed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ks.EdPub, ks.XPub[:]) {
		t.Fatal("the signing key and the agreement key are the same material")
	}
	if bytes.Equal(ks.XPriv[:], seed[:32]) {
		t.Fatal("the agreement private key is the seed itself, unexpanded")
	}
}

// The whole point, at the level the agent works at: an agent restored from the
// same recovery phrase derives the keys its identifier already committed to.
func TestARestoredAgentDerivesTheSameMessagingKeys(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 11)
	}

	original := witnessWithStore(t)
	if err := secureenclave.StoreRootSeed(original.DataDir, seed); err != nil {
		t.Fatal(err)
	}
	ks1, idx, err := original.deriveMessagingKeys("EIdentity")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	// A different device, same recovery phrase, and the branch that was recorded.
	restored := witnessWithStore(t)
	if err := secureenclave.StoreRootSeed(restored.DataDir, seed); err != nil {
		t.Fatal(err)
	}
	if err := restored.recordMessagingKeyIndex("EIdentity", idx); err != nil {
		t.Fatal(err)
	}
	ks2, _, err := restored.deriveMessagingKeys("EIdentity")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	if !sameKeys(ks1, ks2) {
		t.Fatal("a restored agent derived different messaging keys, so its identifier " +
			"commits to keys it no longer holds")
	}
}

// Without key material it refuses rather than inventing keys that cannot be
// recovered. Founding an identity that commits to unrecoverable keys is worse
// than not founding one.
func TestMessagingKeysAreNotInventedWithoutASeed(t *testing.T) {
	s := witnessWithStore(t)
	if _, _, err := s.deriveMessagingKeys("EIdentity"); err == nil {
		t.Fatal("keys were derived with no root seed to derive them from")
	}
}
