package witness

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// AnchoredTEL is the check both a witness (before it stores) and a verifier
// (before it believes) apply. These hand it a key log that seals a registry
// founded by somebody else, which only the issuer-of-record check refuses.

func testRegistry(t *testing.T, issuer string) (raw []byte, registry, said string) {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	nonce, err := keri.MatterQB64(keri.CodeBlake3_256, b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = keri.BuildRegistryInception(keri.RegistryInput{Issuer: issuer, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.VerifyTELEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ev.Subject, ev.SAID
}

func sealing(t *testing.T, prefix, registry, said string) []byte {
	t.Helper()
	seal := json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`, registry, said))
	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: prefix, PriorSAID: said, SN: 1, Data: []json.RawMessage{seal}})
	if err != nil {
		t.Fatal(err)
	}
	return ixn
}

func TestARegistryTheIssuerDidNotFoundIsRefusedEvenWhenItsKeyLogSealsIt(t *testing.T) {
	const issuer = "EIssuer0000000000000000000000000000000000000"
	foreign, reg, said := testRegistry(t, "EOther00000000000000000000000000000000000000")
	kel := [][]byte{sealing(t, issuer, reg, said)}
	if _, err := AnchoredTEL(issuer, kel, [][]byte{foreign}, nil); err == nil {
		t.Fatal("a registry founded by another identity was taken as this issuer's because its key log sealed it")
	}
	own, reg2, said2 := testRegistry(t, issuer)
	got, err := AnchoredTEL(issuer, [][]byte{sealing(t, issuer, reg2, said2)}, [][]byte{own}, nil)
	if err != nil || len(got) != 1 || got[0].AnchorSN != 1 {
		t.Fatalf("the issuer's own sealed registry was refused or misplaced: %+v %v", got, err)
	}
}

// A seal counts only in an interaction event. KERI lets a rotation carry seals
// too, but this contract anchors every registry event in an interaction, so a
// seal found in a rotation's data is not an anchor.
func TestASealInARotationDoesNotAnchorARegistryEvent(t *testing.T) {
	const issuer = "EIssuer0000000000000000000000000000000000000"
	own, reg, said := testRegistry(t, issuer)
	seal := json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`, reg, said))
	next, _ := keri.MatterQB64(keri.CodeBlake3_256, make([]byte, 32))
	rot, err := keri.BuildRotation(keri.RotationInput{Prefix: issuer, Keys: []string{"DKey"}, PriorSAID: said, SN: 1,
		NextDigests: []string{next}, Data: []json.RawMessage{seal}})
	if err != nil {
		t.Skipf("a rotation could not be built for the test: %v", err)
	}
	if _, err := AnchoredTEL(issuer, [][]byte{rot}, [][]byte{own}, nil); err == nil {
		t.Fatal("a seal in a rotation anchored a registry event")
	}
}
