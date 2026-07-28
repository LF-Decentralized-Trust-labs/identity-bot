package backup

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"identity-agent-core/store"
)

// Golden test mnemonic — test vector only, never use in production.
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

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
	wrongKEK, _ := SeedKEKFromMnemonic("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
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

func TestDeriveVaultKEKStableAndDistinct(t *testing.T) {
	seed, err := MnemonicToBIP39Seed(testMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := DeriveVaultKEK(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveVaultKEK(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("vault KEK must be deterministic from the root seed")
	}
	backupKEK, err := DeriveBackupKEK(seed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, backupKEK) {
		t.Fatal("vault KEK must be domain-separated from the backup KEK")
	}
	if _, err := DeriveVaultKEK([]byte("short")); err == nil {
		t.Fatal("short seed must be rejected")
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

// Go <-> keripy golden for derive from root + persisted stable index (monotonic at creation, stored in record).
// Enables root seed phrase + indices for recovery to re-derive pairwise keys. Rust cross deferred.
func TestPairwiseHDGoldenVector(t *testing.T) {
	// Pinned against the SEED, not against a phrase.
	//
	// The other engines pin this same pair, so the expected value below cannot
	// be recomputed on one side alone. Deriving it from a mnemonic here made
	// the vector hostage to a rule about how many words we accept — a policy on
	// what a person may type, which has nothing to do with the derivation being
	// pinned. Changing that rule silently invalidated the vector, which is
	// exactly what a golden vector must not be able to do.
	//
	// These bytes are the BIP39 seed of the all-zero-entropy test phrase, and
	// they do not change.
	s, err := hex.DecodeString(
		"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
			"9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
	if err != nil {
		t.Fatal(err)
	}
	got0, err := DerivePairwiseSeed(s, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want0 := "348de60391d98089828e3ceb3828991313a3a3e3220147e803fd3d4785640f45"
	if fmt.Sprintf("%x", got0) != want0 {
		t.Fatalf("golden[0] mismatch got %x want %s", got0, want0)
	}
	got5, err := DerivePairwiseSeed(s, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got0, got5) {
		t.Fatal("different persisted index must differ")
	}
}

// Test that index allocation is true high-water mark via real Save/Delete roundtrip.
// allocate → Save top → Delete top → allocate must yield strictly larger index (counter survives delete).
func TestRelationshipIndexNoReuseAfterDelete(t *testing.T) {
	tmp := t.TempDir()
	defer os.RemoveAll(tmp)
	fs, err := store.NewFileStore(tmp)
	if err != nil {
		t.Fatal(err)
	}

	// first
	idx1, err := fs.AllocateNextRelationshipIndex("contacts")
	if err != nil || idx1 != 1 {
		t.Fatalf("first got %d err=%v", idx1, err)
	}
	c1 := store.ContactRecord{AID: "c1", RelationshipIndex: idx1}
	if err := fs.SaveContact(c1); err != nil {
		t.Fatal(err)
	}

	// allocate top
	idxTop, err := fs.AllocateNextRelationshipIndex("contacts")
	if err != nil || idxTop != 2 {
		t.Fatalf("top got %d", idxTop)
	}
	ctop := store.ContactRecord{AID: "ctop", RelationshipIndex: idxTop}
	if err := fs.SaveContact(ctop); err != nil {
		t.Fatal(err)
	}

	// delete the top one
	if err := fs.DeleteContact("ctop"); err != nil {
		t.Fatal(err)
	}

	// next must be 3, not reuse 2
	idx3, err := fs.AllocateNextRelationshipIndex("contacts")
	if err != nil || idx3 != 3 {
		t.Fatalf("after real delete-top got %d (must be strictly > 2)", idx3)
	}
}
