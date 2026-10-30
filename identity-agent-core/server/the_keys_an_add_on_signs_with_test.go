package server

import (
	"crypto/ed25519"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// A held key signs exactly as the key itself would, and says its public half.
func TestAHeldKeySignsAsItsKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	k := heldKeyOf(seed)
	if want := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)); k.PublicKey() != want {
		t.Fatalf("public key %s, want %s", k.PublicKey(), want)
	}
	got, err := k.SignString("a message")
	want, _ := login.SignString("a message", seed)
	if err != nil || got != want {
		t.Fatalf("signed string %q (%v), want %q", got, err, want)
	}
	raw := []byte(`{"v":"KERI10JSON000000_","t":"icp"}`)
	got, err = k.SignEvent(raw)
	want, _ = signEventBytes(raw, seed)
	if err != nil || got != want {
		t.Fatalf("signed event %q (%v), want %q", got, err, want)
	}
}

// An identifier that is no asset held here gets no signer.
func TestNoSignerForWhatIsNotHeld(t *testing.T) {
	s := &CoreServer{}
	if _, err := s.assetSigner("Enothing"); err == nil {
		t.Fatal("a signer was given for an asset not held here")
	}
}

// Keys are packed and opened only for what this Identity Agent speaks for:
// its own identity, and not an identifier it does not hold.
func TestNoKeySetForWhatIsNotHeld(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	id, err := s.DataStore.GetIdentity()
	if err != nil || id == nil {
		t.Fatalf("no identity: %v", err)
	}
	if _, err := s.messagingKeysOf(id.AID); err != nil {
		t.Fatalf("its own identity's keys: %v", err)
	}
	if _, err := s.heldKeySet("Enothing"); err == nil {
		t.Fatal("a keyset was used for an identifier this Identity Agent does not speak for")
	}
}
