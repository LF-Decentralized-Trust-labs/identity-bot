package authorisation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

const aDelegator = "EDelegator00000000000000000000000000000000"

func aDelegation(t *testing.T) (dip []byte, id, said, key string) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	key = iacrypto.VerkeyQB64(pub)
	digest, err := iacrypto.NextKeyDigest(iacrypto.VerkeyQB64(nextPub))
	if err != nil {
		t.Fatal(err)
	}
	dip, err = keri.BuildDelegatedInception(keri.DelegationInput{Keys: []string{key}, NextDigests: []string{digest}, Delegator: aDelegator})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(dip)
	if err != nil {
		t.Fatal(err)
	}
	return dip, ev.Identifier, ev.SAID, key
}

func anApproval(t *testing.T, seals ...string) []byte {
	t.Helper()
	data := make([]json.RawMessage, len(seals))
	for i, s := range seals {
		data[i] = json.RawMessage(s)
	}
	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: aDelegator, PriorSAID: "EPrior00000000000000000000000000000000000", SN: 4, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	return ixn
}

// Signing an approval grants a delegation to exactly the identity and key the
// inception derives, read from the inception itself.
func TestSigningADelegationApprovalShowsTheIdentityItApproves(t *testing.T) {
	dip, id, said, key := aDelegation(t)
	ixn := anApproval(t, `{"i":"`+id+`","s":"0","d":"`+said+`"}`)
	got, err := WhatSigningApproves(ixn, dip)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "delegation" || got.Issuer != aDelegator || got.Holder != id || got.PublicKey != key ||
		got.KeyFingerprint != KeyFingerprint(key) || got.SN != 4 || got.Prior == "" {
		t.Fatalf("shown %+v", got)
	}
}

// An interaction that anchors anything else than the inception, or more than
// it, or an inception that is not a delegation, is not signed.
func TestADelegationApprovalThatApprovesAnythingElseIsNotSigned(t *testing.T) {
	dip, id, said, _ := aDelegation(t)
	_, otherID, otherSAID, _ := aDelegation(t)
	for name, ixn := range map[string][]byte{
		"another inception": anApproval(t, `{"i":"`+otherID+`","s":"0","d":"`+otherSAID+`"}`),
		"a later event":     anApproval(t, `{"i":"`+id+`","s":"1","d":"`+said+`"}`),
		"a bare digest":     anApproval(t, `{"d":"`+said+`"}`),
		"two seals":         anApproval(t, `{"i":"`+id+`","s":"0","d":"`+said+`"}`, `{"i":"`+otherID+`","s":"0","d":"`+otherSAID+`"}`),
		"no seal":           anApproval(t),
	} {
		if _, err := WhatSigningApproves(ixn, dip); err == nil {
			t.Errorf("%s was signed", name)
		}
	}
	// Approved by an identity that is not the one it names as its delegator.
	other, err := keri.BuildInteraction(keri.InteractionInput{Prefix: "EAnother00000000000000000000000000000000000", PriorSAID: "EPrior00000000000000000000000000000000000", SN: 4,
		Data: []json.RawMessage{json.RawMessage(`{"i":"` + id + `","s":"0","d":"` + said + `"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WhatSigningApproves(other, dip); err == nil || !strings.Contains(err.Error(), "interaction of") {
		t.Fatalf("an approval by someone other than the delegator: %v", err)
	}
	// Not a delegation at all.
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: []string{"DKey"}})
	if err == nil {
		if _, err := WhatSigningApproves(anApproval(t), icp); err == nil {
			t.Fatal("an ordinary inception was signed as a delegation")
		}
	}
}
