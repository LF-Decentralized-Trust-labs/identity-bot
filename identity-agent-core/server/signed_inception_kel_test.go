package server

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// The key log handed to a service verifies the way such a service checks it —
// signatures and all — and establishes exactly the identifier it is for.
func TestARecordedInceptionIsSignedAsAVerifiableKeyLog(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	signer, _ := keri.NewSoftwareSigner(seed, true)
	next, _ := keri.GenerateSigner(true)
	nextPub, _ := next.PublicKey()
	digest, _ := keri.NextDigest(nextPub)
	pub, _ := signer.PublicKey()
	toad := 1
	event, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub}, NextDigests: []string{digest},
		Witnesses: []string{"BErokYIbJDqV1Ewr3QMHKWokln2aIVRGwTZ3E502pz_v"}, Toad: &toad,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(event)
	var recorded map[string]interface{}
	_ = json.Unmarshal(event, &recorded)

	stream, err := signedInceptionKEL(parsed.Identifier, []map[string]interface{}{recorded}, seed)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := keri.ParseKELStream(stream)
	if err != nil {
		t.Fatal(err)
	}
	state, err := keri.ValidateSignedKEL(messages)
	if err != nil {
		t.Fatalf("the key log does not verify: %v", err)
	}
	if state.Identifier != parsed.Identifier || len(state.Keys) != 1 || state.Keys[0] != pub {
		t.Fatalf("the key log establishes %s with %v", state.Identifier, state.Keys)
	}

	// A record that does not rebuild to its own identifier is refused, not sent.
	recorded["k"] = []interface{}{"DXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"}
	if _, err := signedInceptionKEL(parsed.Identifier, []map[string]interface{}{recorded}, seed); err == nil {
		t.Fatal("a record that is not the identity's own inception was signed anyway")
	}
}
