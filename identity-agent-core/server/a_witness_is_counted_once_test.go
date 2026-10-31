package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// One witness, its receipt stored three times, once under a second spelling
// of its identifier, is one witness. Counted by stored row, as the receipt
// endpoints did, it met a threshold of two alone. (Counting by key rather
// than text is a backstop here: strict decoding already stops the second
// spelling verifying.)
func TestAWitnessUnderTwoSpellingsIsCountedOnce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aid := iacrypto.NonTransferableAIDQB64(pub)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	v := strings.IndexByte(alphabet, aid[1])
	other := aid[:1] + string(alphabet[v&0x0f|1<<4]) + aid[2:]

	said := "EAAAsomeeventidentifier0123456789ABCDEFGHIJK"
	sig, err := iacrypto.MatterFixedQB64("0B", ed25519.Sign(priv, []byte(said)))
	if err != nil {
		t.Fatal(err)
	}
	receipts := []store.WitnessReceiptRecord{
		{EventSAID: said, WitnessAID: aid, CesrSignature: sig},
		{EventSAID: said, WitnessAID: other, CesrSignature: sig},
		{EventSAID: said, WitnessAID: aid, CesrSignature: sig},
	}
	designated := map[string]bool{aid: true, other: true}
	if n := witnessesWhoReceipted(said, receipts, designated); n != 1 {
		t.Fatalf("one witness designated under two spellings was counted %d times", n)
	}
}
