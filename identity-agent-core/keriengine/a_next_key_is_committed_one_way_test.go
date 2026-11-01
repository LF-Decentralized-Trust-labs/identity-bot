package keriengine

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

// A next key belongs to an identity that rotates, so a non-transferable (code
// B) key is refused as one rather than committed to as written. Committing to
// it would leave two digests of the same key in this codebase, one over the B
// text and one over the D text, and an identity committed one way and checked
// the other could never rotate.
func TestANonTransferableNextKeyIsRefused(t *testing.T) {
	pub, next, _ := keys(t)
	raw, err := keri.MatterRaw(keri.CodeEd25519, next, 32)
	if err != nil {
		t.Fatal(err)
	}
	nonTransferable := iacrypto.NonTransferableAIDQB64(raw)

	if _, err := New().CreateInceptionNamed(pub, nonTransferable, "a"); err == nil {
		t.Fatal("an inception committing to a non-transferable next key was made")
	}

	e := New()
	if _, err := e.CreateInceptionNamed(pub, next, "b"); err != nil {
		t.Fatal(err)
	}
	_, after, _ := keys(t)
	afterRaw, err := keri.MatterRaw(keri.CodeEd25519, after, 32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Rotate(drivers.RotationRequest{Name: "b", NewPublicKey: next,
		NewNextPublicKey: iacrypto.NonTransferableAIDQB64(afterRaw)}); err == nil {
		t.Fatal("a rotation committing to a non-transferable next key was made")
	}
}

// The commitment made at founding is the one a rotation opens, through the one
// next-key digest, whichever spelling of the key the caller held.
func TestTheFoundingCommitmentIsTheDigestARotationOpens(t *testing.T) {
	pub, next, _ := keys(t)
	nextRaw, err := keri.MatterRaw(keri.CodeEd25519, next, 32)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := New().CreateInceptionNamed(pub, base64.StdEncoding.EncodeToString(nextRaw), "a")
	if err != nil {
		t.Fatal(err)
	}
	want, err := keri.NextDigest(next)
	if err != nil {
		t.Fatal(err)
	}
	viaCore, err := iacrypto.NextKeyDigest(next)
	if err != nil {
		t.Fatal(err)
	}
	if inc.NextKeyDigest != want || viaCore != want {
		t.Fatalf("the founding committed to %s, keri-go digests the key as %s and the core as %s",
			inc.NextKeyDigest, want, viaCore)
	}
}
