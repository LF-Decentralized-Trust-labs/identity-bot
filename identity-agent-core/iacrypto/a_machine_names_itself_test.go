package iacrypto

import (
	"bytes"
	"strings"
	"testing"
)

// A machine's own key is secp256r1, and it has to be named the way the rest of
// the world names one.
//
// The vector below is not computed here — it is what keripy 1.1.17 produces for
// the same compressed point, and this test exists so that if our encoding ever
// drifts from the reference implementation the difference shows up as a failed
// assertion rather than as an identifier somebody else's verifier rejects.
//
// That is not hypothetical. Before this, the enclave's 65-byte P-256 point was
// encoded under the Ed25519 code "B", which produced an 88-character identifier
// where the specification says 44. Nothing errored. The agent then rejected its
// own identifier and blamed whoever passed it in.
func TestAMachineNamesItselfTheWayKeripyDoes(t *testing.T) {
	// A compressed P-256 point: the 0x02 prefix records an even Y, then X.
	point := make([]byte, 33)
	point[0] = 0x02
	for i := 1; i < 33; i++ {
		point[i] = byte(i - 1)
	}

	// What keripy 1.1.17 produces for that point, obtained by running it:
	//
	//   Matter(raw=point, code=MtrDex.ECDSA_256r1N).qb64
	//   Matter(raw=point, code=MtrDex.ECDSA_256r1).qb64
	//
	// Pinned rather than recomputed, so a change to our encoder that still
	// round-trips against itself is still caught. A self-consistent encoder that
	// disagrees with the reference is the failure that matters, because it looks
	// correct from inside this package and is rejected by everybody else.
	const (
		keripyAID    = "1AAIAgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
		keripyVerkey = "1AAJAgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
	)

	t.Run("it encodes exactly what keripy encodes", func(t *testing.T) {
		aid, err := MachineAIDQB64(point)
		if err != nil {
			t.Fatal(err)
		}
		if aid != keripyAID {
			t.Fatalf("identifier disagrees with keripy:\n want %s\n got  %s", keripyAID, aid)
		}
		verkey, err := MachineVerkeyQB64(point)
		if err != nil {
			t.Fatal(err)
		}
		if verkey != keripyVerkey {
			t.Fatalf("verification key disagrees with keripy:\n want %s\n got  %s", keripyVerkey, verkey)
		}
	})

	t.Run("the identifier is the size the code declares", func(t *testing.T) {
		aid, err := MachineAIDQB64(point)
		if err != nil {
			t.Fatalf("a valid compressed point must encode: %v", err)
		}
		if !strings.HasPrefix(aid, CodeP256N) {
			t.Fatalf("a machine identifier must carry the secp256r1 code %q, got %q", CodeP256N, aid)
		}
		// 48 = 4 code characters + 44 of body. The Ed25519 form is 44 in total,
		// and confusing the two is what produced the malformed value this fixes.
		if len(aid) != 48 {
			t.Fatalf("a secp256r1 identifier is 48 characters, got %d (%q)", len(aid), aid)
		}
	})

	t.Run("it round-trips back to the same key", func(t *testing.T) {
		aid, err := MachineAIDQB64(point)
		if err != nil {
			t.Fatal(err)
		}
		back, err := KeyFromMachineAID(aid)
		if err != nil {
			t.Fatalf("an identifier this package produced must decode here: %v", err)
		}
		if !bytes.Equal(back, point) {
			t.Fatalf("the key did not survive the round trip:\n want %x\n got  %x", point, back)
		}
	})

	t.Run("an uncompressed point is compressed rather than refused", func(t *testing.T) {
		// What Apple actually hands back: 0x04, then X, then Y. The parity of the
		// final byte decides the compressed prefix, so an odd Y must give 0x03.
		uncompressed := make([]byte, 65)
		uncompressed[0] = 0x04
		copy(uncompressed[1:33], point[1:])
		uncompressed[64] = 0x01 // odd Y

		got, err := CompressP256(uncompressed)
		if err != nil {
			t.Fatalf("the enclave's own format must be accepted: %v", err)
		}
		if got[0] != 0x03 {
			t.Fatalf("an odd Y is recorded as 0x03, got 0x%02x", got[0])
		}
		if !bytes.Equal(got[1:], uncompressed[1:33]) {
			t.Fatal("X must be carried through unchanged")
		}
	})

	t.Run("a key of the wrong size is refused rather than encoded", func(t *testing.T) {
		// THE WHOLE POINT. This is the value that used to sail through: a 65-byte
		// P-256 point under an Ed25519 code, producing a well-formed-looking name
		// for a key nothing could recover.
		wrong := make([]byte, 65)
		wrong[0] = 0x04
		if s, err := MatterFixedQB64("B", wrong); err == nil {
			t.Fatalf("a 65-byte value must not encode under a 32-byte code; got %q", s)
		}
		if _, err := MatterFixedQB64("D", make([]byte, 33)); err == nil {
			t.Fatal("a 33-byte value must not encode under the Ed25519 verkey code")
		}
		if _, err := MatterFixedQB64(CodeP256N, make([]byte, 32)); err == nil {
			t.Fatal("a 32-byte value must not encode under a 33-byte code")
		}
	})

	t.Run("a machine identifier is not mistaken for an Ed25519 one", func(t *testing.T) {
		aid, err := MachineAIDQB64(point)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := KeyFromNonTransferableAID(aid); err == nil {
			t.Fatal("the Ed25519 decoder must refuse a secp256r1 identifier rather than " +
				"returning bytes that are not the key")
		}
		ed := make([]byte, 32)
		edAID := NonTransferableAIDQB64(ed)
		if _, err := KeyFromMachineAID(edAID); err == nil {
			t.Fatal("the machine decoder must refuse an Ed25519 identifier")
		}
	})
}
