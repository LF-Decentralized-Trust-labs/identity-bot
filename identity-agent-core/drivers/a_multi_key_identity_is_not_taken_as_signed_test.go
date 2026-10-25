package drivers

import (
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A log carries one signature per event, so one member of a two-key identity
// signing its inception must not establish the identity as signed: that would
// let any one member sign for all of them.
func TestOneMemberOfATwoKeyIdentityDoesNotSignForIt(t *testing.T) {
	a, _ := keri.GenerateSigner(true)
	b, _ := keri.GenerateSigner(true)
	next, _ := keri.GenerateSigner(true)
	pa, _ := a.PublicKey()
	pb, _ := b.PublicKey()
	pn, _ := next.PublicKey()
	dn, _ := keri.NextDigest(pn)
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pa, pb}, Isith: []byte(`"2"`), NextDigests: []string{dn},
		Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := a.Sign(icp)
	qb64, _ := keri.MatterQB64(keri.CodeEd25519Sig, sig)

	got, err := ValidateKELFromBytes(ValidateKELInput{
		AID: ev.Identifier, RawEvents: [][]byte{icp}, CesrSignatures: []string{qb64},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatalf("one member's signature verified a two-key identity, key %s", got.CurrentPublicKey)
	}
}

// An indexed signature naming a second key cannot be checked against a
// single-key log's only key and taken as that key's.
func TestASignatureIndexedToAnotherKeyIsRefused(t *testing.T) {
	sig := "AB" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := decodeCesrSignature(sig[:88]); err == nil {
		t.Fatal("a signature indexed to the second key was decoded as the first key's")
	}
}
