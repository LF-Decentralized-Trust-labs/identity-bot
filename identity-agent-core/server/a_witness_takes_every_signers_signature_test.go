package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A witness is sent every signer's signature over an event of an identity with
// several, in cesr_signatures, and receipts it only when they meet its
// threshold.
func TestAWitnessTakesEverySignersSignature(t *testing.T) {
	bob := startPeer(t, "bob")
	var signers []keri.Signer
	var keys, next []string
	for i := 0; i < 4; i++ {
		s, err := keri.GenerateSigner(true)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, s)
	}
	for i := 0; i < 2; i++ {
		pub, _ := signers[i].PublicKey()
		keys = append(keys, pub)
		nextPub, _ := signers[i+2].PublicKey()
		d, err := keri.NextDigest(nextPub)
		if err != nil {
			t.Fatal(err)
		}
		next = append(next, d)
	}
	toad := 1
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: keys, NextDigests: next,
		Witnesses: []string{bob.witnessKey}, Toad: &toad,
		Isith: json.RawMessage(`"2"`), Nsith: json.RawMessage(`"2"`)})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	bob.willWitnessFor(t, ev.Identifier)
	sign := func(i int) string {
		sig, err := signers[i].Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		qb, err := keri.EncodeIndexedSignature(sig, keri.SamePlace(i))
		if err != nil {
			t.Fatal(err)
		}
		return qb
	}
	post := func(body map[string]interface{}) int {
		body["aid"] = ev.Identifier
		body["event_b64"] = base64.StdEncoding.EncodeToString(raw)
		b, _ := json.Marshal(body)
		resp, err := http.Post(bob.base+"/api/witness/event", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := post(map[string]interface{}{"cesr_signature": sign(0)}); code == http.StatusOK {
		t.Fatal("one of two signers' signatures was receipted against kt 2")
	}
	if code := post(map[string]interface{}{"cesr_signature": sign(0),
		"cesr_signatures": []string{sign(1)}}); code != http.StatusOK {
		t.Fatalf("both signers' signatures were refused: %d", code)
	}
}
