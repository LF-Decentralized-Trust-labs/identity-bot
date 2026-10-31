package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
)

// A message received from a peer that writes the CESR body_hash, the form
// writing moves to in a later release, is kept with its proof, and its sender
// is proved. An Identity Agent on the earlier form therefore already reads
// what an upgraded peer sends, and new messages from the same sender still
// arrive and prove theirs.
//
// The receipt is made as the inbound handler makes it, from the signed form
// such a peer sends: keep the proof, store the message, log the receipt.
func TestAProofKeptInTheCESRBodyHashFormProvesItsSender(t *testing.T) {
	m := newMessaging(t)
	m.anchored(t)
	ks, err := m.sender.keySetFor(m.senderAID)
	if err != nil {
		t.Fatal(err)
	}
	senderDID, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	jwm := &didcomm.JWM{
		ID: "msg-from-a-peer-writing-cesr", Type: didcomm.TypeNotification,
		From: "did:keri:" + m.senderAID, To: []string{"did:keri:" + m.receiverAID},
		CreatedTime: time.Now().UTC().Format(time.RFC3339),
		ExpiresTime: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Body:        json.RawMessage(`{"title":"from an upgraded peer"}`),
	}
	canonical, _ := json.Marshal(jwm)
	cesr := iacrypto.Blake3QB64Must(jwm.Body)
	input := append(append([]byte{}, canonical...), cesr...)
	signed, _ := json.Marshal(map[string]any{
		"jwm": json.RawMessage(canonical), "body_hash": cesr,
		"ed_sig":    base64.RawURLEncoding.EncodeToString(ed25519.Sign(ks.EdPriv, input)),
		"mldsa_sig": base64.RawURLEncoding.EncodeToString(mldsa65.Scheme().Sign(ks.DsaPriv, input, nil)),
	})
	if _, err := didcomm.VerifySignedMessage(senderDID, signed); err != nil {
		t.Fatalf("the signed form an upgraded peer sends does not verify: %v", err)
	}

	proof := m.receiver.proofOfReceipt(m.senderAID, senderDID, signed)
	if proof == nil {
		t.Fatal("no proof was kept")
	}
	m.receiver.storeInboundAsNotification(m.senderAID, m.receiverAID, jwm, true, proof)
	m.receiver.recordTraffic(m.senderAID, jwm.ID, "", "didcomm.message.received", "ok",
		jwm.Type+" to "+m.receiverAID, receiptBinding(jwm.ID, *proof))

	kept, err := m.receiver.DataStore.GetNotification(jwm.ID)
	if err != nil || kept == nil {
		t.Fatalf("the message was not kept: %v", err)
	}
	if _, _, err := m.receiver.provedSender(*kept); err != nil {
		t.Fatalf("a proof kept in the CESR body_hash form does not prove its sender: %v", err)
	}
	after := m.send(t, `{"title":"after the change"}`)
	if _, _, err := m.receiver.provedSender(after); err != nil {
		t.Fatalf("a new message from the same sender does not prove its sender: %v", err)
	}
}
