package backup

import (
	"bytes"
	"fmt"
	"testing"
)

// Golden test mnemonic — test vector only, never use in production.
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestEnvelopeEncryptionRoundTrip(t *testing.T) {
	bek, err := NewBEK()
	if err != nil {
		t.Fatal(err)
	}
	seedKEK, err := SeedKEKFromMnemonic(testMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, nonce, err := WrapBEK(seedKEK, bek)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := UnwrapBEK(seedKEK, wrapped, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bek, unwrapped) {
		t.Fatal("BEK round-trip mismatch")
	}
}

func TestWrongSeedFailsUnwrap(t *testing.T) {
	bek, _ := NewBEK()
	seedKEK, _ := SeedKEKFromMnemonic(testMnemonic)
	wrapped, nonce, _ := WrapBEK(seedKEK, bek)
	wrongKEK, _ := SeedKEKFromMnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow")
	_, err := UnwrapBEK(wrongKEK, wrapped, nonce)
	if err == nil {
		t.Fatal("expected unwrap failure with wrong seed")
	}
}

func TestPayloadEncryptDecrypt(t *testing.T) {
	bek, _ := NewBEK()
	plain := []byte(`{"sections":[{"name":"identity_state","data":"e30="}]}`)
	ct, nonce, err := EncryptPayload(bek, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecryptPayload(bek, ct, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, out) {
		t.Fatal("payload round-trip mismatch")
	}
}

func TestPassphraseSlotIndependentOfSeed(t *testing.T) {
	bek, _ := NewBEK()
	seedKEK, _ := SeedKEKFromMnemonic(testMnemonic)
	wrappedSeed, nonceSeed, _ := WrapBEK(seedKEK, bek)

	params := DefaultArgon2Params()
	salt, _ := randomBytes(Argon2SaltLen)
	passKEK, err := DerivePassphraseKEK("correct horse battery staple", salt, params)
	if err != nil {
		t.Fatal(err)
	}
	wrappedPass, noncePass, _ := WrapBEK(passKEK, bek)

	// Same BEK, different wraps
	unwrappedSeed, err := UnwrapBEK(seedKEK, wrappedSeed, nonceSeed)
	if err != nil {
		t.Fatal(err)
	}
	unwrappedPass, err := UnwrapBEK(passKEK, wrappedPass, noncePass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrappedSeed, unwrappedPass) {
		t.Fatal("both slots must unwrap to same BEK")
	}
}

func TestDeriveBackupKEKStable(t *testing.T) {
	a, err := SeedKEKFromMnemonic(testMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SeedKEKFromMnemonic(testMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("backup KEK must be deterministic from mnemonic")
	}
}

func TestPairwiseHDDeterministic(t *testing.T) {
	seed, err := MnemonicToBIP39Seed(testMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := DerivePairwiseSeed(seed, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DerivePairwiseSeed(seed, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("pairwise seed not deterministic")
	}
	c, err := DerivePairwiseSeed(seed, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("different contact index must yield different seed")
	}
}

// Go <-> keripy golden vector for the HD pairwise derivation (desktop/keripy path).
// Proves deterministic SLIP-0010 from root and matches what the engine (via driver icp on derived pub) expects.
// Rust (mobile) cross-engine vector deferred to mobile QA (2026-06-23 deviation note).
func TestPairwiseHDGoldenVector(t *testing.T) {
	m := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	s, err := MnemonicToBIP39Seed(m, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DerivePairwiseSeed(s, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "348de60391d98089828e3ceb3828991313a3a3e3220147e803fd3d4785640f45"
	if fmt.Sprintf("%x", got) != want {
		t.Fatalf("Go/keripy golden mismatch got %x want %s (update if path constants change)", got, want)
	}
}