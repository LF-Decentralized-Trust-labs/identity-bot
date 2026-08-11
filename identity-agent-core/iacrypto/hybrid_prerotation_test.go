package iacrypto

import (
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A pre-rotation commitment is only worth anything if the rotation that has to
// satisfy it can reproduce it.
//
// These tests exist because the commitment was once the digest of the next
// key's raw bytes while the rotation path digests the key's qb64 text. Both
// were individually reasonable and every test passed, because nothing checked
// the two against each other — the inception tests only asked whether a digest
// came out, and there was no rotation test at all. The failure would have
// surfaced the first time a hybrid identity tried to rotate, which is the worst
// possible moment: the commitment is already published and cannot be amended,
// so the identity holds keys it can prove it owns and can never use.
//
// So these assert the join, not either side.

func TestTheEd25519CommitmentIsWhatARotationWouldReproduce(t *testing.T) {
	m := SyntheticHybridKeyMaterial(1)

	keys, err := materialToCESR(m)
	if err != nil {
		t.Fatal(err)
	}

	// What a rotation publishes: the next key, as qb64 text.
	published, err := ed25519VerferQB64(m.NextEd25519SigningRaw)
	if err != nil {
		t.Fatal(err)
	}
	// What a verifier does with it.
	want, err := keri.NextDigest(published)
	if err != nil {
		t.Fatal(err)
	}

	if keys.NextEd25519Digest != want {
		t.Fatalf("the inception committed to %s but a rotation publishing %s derives %s, "+
			"so the rotation would be refused and the identity could never move off "+
			"its first key", keys.NextEd25519Digest, published, want)
	}
}

func TestTheMLDSACommitmentIsWhatARotationWouldReproduce(t *testing.T) {
	m := SyntheticHybridKeyMaterial(1)

	keys, err := materialToCESR(m)
	if err != nil {
		t.Fatal(err)
	}

	published, err := EncodeLargeFixed(CESRMLDSA65Verkey, m.NextMLDSA65SigningRaw, MLDSA65VerkeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	want, err := keri.NextDigest(published)
	if err != nil {
		t.Fatal(err)
	}

	if keys.NextMLDSA65Digest != want {
		t.Fatalf("the inception committed to %s but a rotation publishing the post-quantum "+
			"key derives %s", keys.NextMLDSA65Digest, want)
	}
}

// The raw-bytes digest is what the code used to produce. Naming it here means
// that if anyone reintroduces it the test says which mistake was made rather
// than only that two opaque strings differ.
func TestCommittingToTheRawKeyBytesIsNotTheSameThing(t *testing.T) {
	m := SyntheticHybridKeyMaterial(1)

	overRawBytes, err := Blake3QB64(m.NextEd25519SigningRaw)
	if err != nil {
		t.Fatal(err)
	}
	published, err := ed25519VerferQB64(m.NextEd25519SigningRaw)
	if err != nil {
		t.Fatal(err)
	}
	overTheText, err := keri.NextDigest(published)
	if err != nil {
		t.Fatal(err)
	}

	if overRawBytes == overTheText {
		t.Fatal("digesting the raw key and digesting its qb64 text gave the same answer, " +
			"which would make this whole class of mistake undetectable")
	}
}

// Every hybrid commitment is a digest, so it is an 'E' identifier of the usual
// length. A commitment of the wrong shape is refused by verifiers before its
// value is ever considered.
func TestBothCommitmentsAreWellFormedDigests(t *testing.T) {
	keys, err := materialToCESR(SyntheticHybridKeyMaterial(1))
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]string{
		"ed25519": keys.NextEd25519Digest,
		"ml-dsa":  keys.NextMLDSA65Digest,
	} {
		if len(d) != 44 || d[0] != 'E' {
			t.Errorf("the %s commitment is %q, which is not a Blake3 digest", name, d)
		}
	}
}
