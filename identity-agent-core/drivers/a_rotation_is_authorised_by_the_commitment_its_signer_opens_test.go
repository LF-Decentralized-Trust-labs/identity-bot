package drivers

import (
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A rotation is authorised by the prior commitments its signing keys open,
// read from the place each signature names in the prior next-key list, as
// keripy judges it. A key listed in the rotation opens nothing by being listed.

// partialRotation founds an identity committing to two next keys, either of
// which alone meets its next threshold, and rotates to the second of them
// alone: the rotation's only key sits first in its key list and opens the
// second commitment.
func partialRotation(t *testing.T) (aid string, raws [][]byte, sign func(i int, at keri.SignaturePlace) string) {
	t.Helper()
	gen := func() (keri.Signer, string, string) {
		s, err := keri.GenerateSigner(true)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := s.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		d, err := keri.NextDigest(pub)
		if err != nil {
			t.Fatal(err)
		}
		return s, pub, d
	}
	founder, founderKey, _ := gen()
	_, _, unused := gen()
	revealed, revealedKey, revealedDigest := gen()
	_, _, after := gen()

	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{founderKey}, NextDigests: []string{unused, revealedDigest},
		Nsith: []byte(`"1"`), Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	icpEv, err := keri.ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: icpEv.Identifier, Keys: []string{revealedKey}, PriorSAID: icpEv.SAID, SN: 1,
		NextDigests: []string{after},
	})
	if err != nil {
		t.Fatal(err)
	}
	raws = [][]byte{icp, rot}
	signers := []keri.Signer{founder, revealed}
	sign = func(i int, at keri.SignaturePlace) string {
		sig, err := signers[i].Sign(raws[i])
		if err != nil {
			t.Fatal(err)
		}
		qb64, err := keri.EncodeIndexedSignature(sig, at)
		if err != nil {
			t.Fatal(err)
		}
		return qb64
	}
	return icpEv.Identifier, raws, sign
}

// Signed with the plain A code, the rotation's signature names the first
// commitment, which its key does not open, so no committed key has authorised
// the rotation. Before, a rotation whose key appeared anywhere in the
// commitment and whose signature verified was accepted.
func TestARotationWhoseSignatureOpensNoCommitmentIsRefused(t *testing.T) {
	aid, raws, sign := partialRotation(t)
	got, err := ValidateKELFromBytes(ValidateKELInput{
		AID: aid, RawEvents: raws,
		CesrSignatures: []string{sign(0, keri.SamePlace(0)), sign(1, keri.SamePlace(0))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified || got.LogSound {
		t.Fatal("a rotation whose signature opens none of the prior commitments was verified")
	}
}

// Signed with 2A, key 0 opening commitment 1, the same rotation is authorised.
// Before, the two-place code was not read at all.
func TestARotationOpeningTheSecondCommitmentWithTwoPlacesVerifies(t *testing.T) {
	aid, raws, sign := partialRotation(t)
	rotSig := sign(1, keri.SignaturePlace{Index: 0, Ondex: 1})
	if rotSig[:2] != "2A" {
		t.Fatalf("expected a 2A signature, got %s", rotSig[:2])
	}
	got, err := ValidateKELFromBytes(ValidateKELInput{
		AID: aid, RawEvents: raws, CesrSignatures: []string{sign(0, keri.SamePlace(0)), rotSig},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.KelVerified {
		t.Fatalf("a rotation opening its commitment through a 2A signature was refused: %v",
			got.ValidationErrors)
	}
	if got.CurrentPublicKey == "" {
		t.Fatal("the verified log reports no current key")
	}
}

// A current-only signature (B) counts toward the signing threshold and opens
// nothing: it signs an inception, and cannot authorise a rotation.
func TestACurrentOnlySignatureCannotAuthoriseARotation(t *testing.T) {
	aid, raws, sign := partialRotation(t)
	b := keri.SignaturePlace{Index: 0, CurrentOnly: true}

	icpOnly, err := ValidateKELFromBytes(ValidateKELInput{
		AID: aid, RawEvents: raws[:1], CesrSignatures: []string{sign(0, b)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !icpOnly.KelVerified {
		t.Fatalf("an inception signed with a current-only signature was refused: %v",
			icpOnly.ValidationErrors)
	}

	got, err := ValidateKELFromBytes(ValidateKELInput{
		AID: aid, RawEvents: raws, CesrSignatures: []string{sign(0, keri.SamePlace(0)), sign(1, b)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified || got.LogSound {
		t.Fatal("a rotation signed only with a current-only signature was verified")
	}
}
