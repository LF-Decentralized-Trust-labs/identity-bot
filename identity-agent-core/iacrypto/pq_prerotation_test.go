package iacrypto

import (
	"bytes"
	"testing"
)

// The encoding a validator will recompute against has to be the right width, or
// the commitment can never be satisfied. This is the failure the old code made:
// a body that is not a whole number of base64 quadruples still looks like a key.
func TestMLDSA65VerkeyEncodesToTheSpecifiedWidth(t *testing.T) {
	pub := make([]byte, MLDSA65VerkeyBytes)
	qb64, err := MLDSA65VerkeyQB64(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(qb64) != 2608 {
		t.Errorf("encoded width is %d, want 2608", len(qb64))
	}
	body := len(qb64) - len(ProposedMLDSA65Verkey)
	if body%4 != 0 {
		t.Errorf("body is %d characters, which is not a whole number of base64 quadruples", body)
	}
	if got := qb64[:4]; got != ProposedMLDSA65Verkey {
		t.Errorf("code is %q, want %q", got, ProposedMLDSA65Verkey)
	}
}

// The bug this replaces, kept as a test so nobody reaches for that helper again
// for a primitive whose size does not divide by three.
func TestEncodeLargeFixedIsWrongForAnMLDSAKey(t *testing.T) {
	pub := make([]byte, MLDSA65VerkeyBytes)
	bad, err := EncodeLargeFixed("1PDA", pub, MLDSA65VerkeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if (len(bad)-4)%4 == 0 {
		t.Fatal("expected the lead-byte-less encoding to be malformed; it no longer is, " +
			"so this test and the comment it guards are stale")
	}
	good, err := MLDSA65VerkeyQB64(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) == len(good) {
		t.Errorf("the two encodings should differ in width; both are %d", len(bad))
	}
}

// Derivation must be deterministic, or an owner who restores from their
// recovery phrase holds a commitment they cannot satisfy.
func TestPostQuantumNextKeyIsReproducibleFromTheSameSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 64)

	first, err := PostQuantumNextKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	again, err := PostQuantumNextKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != again.Digest {
		t.Errorf("same seed produced different commitments:\n  %s\n  %s", first.Digest, again.Digest)
	}
	if first.Verkey != again.Verkey {
		t.Error("same seed produced a different key")
	}

	other := bytes.Repeat([]byte{8}, 64)
	different, err := PostQuantumNextKeyFromSeed(other)
	if err != nil {
		t.Fatal(err)
	}
	if different.Digest == first.Digest {
		t.Error("a different seed produced the same commitment, so the seed is being ignored")
	}
}

// The commitment must be over the key's qb64 TEXT. Taken over the raw bytes it
// still looks like a digest and nothing can ever satisfy it.
func TestCommitmentIsTakenOverTheEncodedKeyNotTheRawBytes(t *testing.T) {
	seed := bytes.Repeat([]byte{3}, 64)
	pq, err := PostQuantumNextKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	overText, err := Blake3QB64([]byte(pq.Verkey))
	if err != nil {
		t.Fatal(err)
	}
	if pq.Digest != overText {
		t.Errorf("commitment is not the digest of the encoded key")
	}

	raw, err := KeyFromVerkeyQB64(pq.Verkey)
	if err == nil && len(raw) > 0 {
		overRaw, derr := Blake3QB64(raw)
		if derr == nil && pq.Digest == overRaw {
			t.Error("commitment was taken over the raw key bytes; a validator recomputes " +
				"it over the qb64 text, so this could never be rotated against")
		}
	}
}

// A digest is a digest whatever it was taken over — which is the whole reason a
// post-quantum key can be committed to before its code exists.
func TestTheCommitmentIsAnOrdinaryDigestWidth(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, 64)
	pq, err := PostQuantumNextKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	classical, err := NextKeyDigest("DAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g")
	if err != nil {
		t.Fatal(err)
	}
	if len(pq.Digest) != len(classical) {
		t.Errorf("a commitment to a 1952-byte key is %d characters and a commitment to a "+
			"32-byte key is %d; they must be identical in width or the point does not hold",
			len(pq.Digest), len(classical))
	}
}
