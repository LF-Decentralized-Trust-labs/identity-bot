package login

import (
	"strings"
	"testing"

	"identity-agent-core/secureenclave"
)

// ADR-069. The assertion a person's Identity Agent signs names each credential
// it presents by digest, so the text a page is handed holds none; the
// credentials themselves go in the post, beside it.
func TestAnAssertionSignsTheDigestsOfTheCredentialsAndTheCredentialsTravelBesideIt(t *testing.T) {
	store, err := NewRelationshipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Store: store, DevRelay: "http://127.0.0.1:8765", dataDir: t.TempDir()}
	root := make([]byte, 64)
	copy(root, "testrootseedforhdderivationtestonly0000000000000000000000000000")
	if err := secureenclave.StoreDeviceLocalSeed(h.dataDir, root); err != nil {
		t.Fatal(err)
	}
	const body = "SECRET-CREDENTIAL-BODY"
	h.HeldCredentials = func() []PresentedCredential {
		return []PresentedCredential{{SAID: "ECredA", SchemaSAID: "ESchema", Status: "issued", AcdcJsonB64: body}}
	}
	bundle := &ChallengeBundle{
		V: "ASK1", T: 1, SiteAID: "EsiteAAA", SiteOOBI: "https://a.example/oobi/EsiteAAA",
		Audience: "https://a.example", Nonce: "nonceA",
		RequestedCredentials: []RequestedCredential{{SchemaSAID: "ESchema"}},
	}
	rel, err := h.getOrCreateRelationship("EsiteAAA", bundle)
	if err != nil {
		t.Fatal(err)
	}
	a, creds, err := h.BuildAssertionWithCredentials(rel, bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.PresentedACDCs) != 1 || a.PresentedACDCs[0] != "ECredA" || len(creds) != 1 {
		t.Fatalf("assertion presents %v with %d credentials, want the digest ECredA", a.PresentedACDCs, len(creds))
	}

	post, err := SignInPostBody(a, creds)
	if err != nil {
		t.Fatal(err)
	}
	raw, read, posted, err := ReadSignInPost(post)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), body) {
		t.Errorf("the assertion text holds a credential's body: %s", raw)
	}
	if len(posted) != 1 || posted[0].AcdcJsonB64 != body {
		t.Errorf("the credential did not travel beside the assertion: %v", posted)
	}
	if !DigestsOnly(read) {
		t.Error("an assertion naming digests was read as carrying credentials")
	}
	// The signature covers the digests, and the site checks it as it checks any.
	if res := VerifyAssertion(read, bundle.Nonce, bundle.Audience, bundle.SiteAID, 300); !res.Valid {
		t.Fatalf("an assertion naming digests did not verify: %s", res.Reason)
	}
	// Swapping the named digest after signing breaks the signature.
	read.PresentedACDCs = []interface{}{"ECredB"}
	if res := VerifyAssertion(read, bundle.Nonce, bundle.Audience, bundle.SiteAID, 300); res.Valid {
		t.Error("an assertion verified after the credential it names was swapped")
	}

	// With nothing presented the post is the bare assertion, as before.
	bare, _ := SignInPostBody(a, nil)
	if _, _, got, err := ReadSignInPost(bare); err != nil || got != nil {
		t.Errorf("a bare assertion read as %v, %v", got, err)
	}
	// An assertion in the form before ADR-069 is still read, and is not digests only.
	old := read
	old.PresentedACDCs = []interface{}{map[string]interface{}{"said": "ECredA"}}
	if DigestsOnly(old) {
		t.Error("an assertion carrying a credential whole was taken for digests only")
	}
	// A wrapper is read as strictly as an assertion.
	if _, _, _, err := ReadSignInPost([]byte(`{"assertion":{},"credentials":[],"extra":1}`)); err == nil {
		t.Error("a sign-in post with an unknown field was read")
	}
}
