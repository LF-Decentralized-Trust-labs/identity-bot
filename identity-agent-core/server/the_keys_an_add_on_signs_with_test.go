package server

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/coretypes"
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

// Opening an envelope sealed to this Identity Agent tells "its own keys
// cannot be read right now", which is its fault, from "this envelope is not
// one sealed to it", which is the sender's, so the caller can answer 503 for
// the first and 403 for the second.
func TestOpeningASealedEnvelopeSaysWhoseFaultItIs(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	id, err := s.DataStore.GetIdentity()
	if err != nil || id == nil {
		t.Fatalf("no identity: %v", err)
	}
	to, err := s.messagingKeysOf(id.AID)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := didcomm.GenerateKeySet("Esender")
	if err != nil {
		t.Fatal(err)
	}
	from, err := sender.DID()
	if err != nil {
		t.Fatal(err)
	}
	env, err := didcomm.PackAuthcrypt(sender, to, &didcomm.JWM{ID: "m1", Type: didcomm.TypeBodyEnrolment, Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.openSealedTo(id.AID, from, env); err != nil {
		t.Fatalf("a genuine envelope did not open: %v", err)
	}

	other, _ := didcomm.GenerateKeySet("Eother")
	otherDID, _ := other.DID()
	_, err = s.openSealedTo(id.AID, otherDID, env)
	if err == nil || errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Fatalf("an envelope not from the sender named was refused as the keys being unreadable: %v", err)
	}

	if err := os.WriteFile(s.didcommKeysPath(), []byte(`{"`+id.AID+`":"not a keyset"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.openSealedTo(id.AID, from, env); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Fatalf("unreadable keys were not reported as such: %v", err)
	}
}
