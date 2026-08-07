package didwebs

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildDidJSONSEAM17(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	in := PublishInput{
		AID: "EPairwiseAID00000000000000000000000001",
		Host: "k7f2pq9r.relay.grapeid.org",
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
		SequenceNumber: 0,
	}
	raw, err := BuildDidJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	id := doc["id"].(string)
	if !strings.HasPrefix(id, "did:webs:") {
		t.Fatalf("id %s", id)
	}
	vm := doc["verificationMethod"].([]interface{})[0].(map[string]interface{})
	mb := vm["publicKeyMultibase"].(string)
	if !strings.HasPrefix(mb, "z") {
		t.Fatalf("multibase %s", mb)
	}
}

func TestBuildCesrStreamFailOpenHeader(t *testing.T) {
	raw, complete, hdr := BuildCesrStream(PublishInput{
		KELEvents: []map[string]interface{}{{"t": "icp"}},
		WitnessReceipts: 2, WitnessThreshold: 5,
	})
	if complete {
		t.Fatal("expected incomplete stream")
	}
	if hdr != "2/5" {
		t.Fatalf("hdr %s", hdr)
	}
	if len(raw) == 0 {
		t.Fatal("empty stream")
	}
}