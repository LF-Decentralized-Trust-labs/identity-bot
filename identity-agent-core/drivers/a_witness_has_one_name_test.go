package drivers

import (
	"strings"
	"testing"
)

// otherSpelling is the witness identifier aid with one of the 2 lead bits after
// its code set: the same key bytes, written a second way.
func otherSpelling(aid string) string {
	v := strings.IndexByte(b64url, aid[1])
	return aid[:1] + string(b64url[v&0x0f|1<<4]) + aid[2:]
}

// A witness identifier has one spelling. The second one, read as the same key,
// verified the witness's own receipts.
func TestAReceiptUnderASecondSpellingOfTheWitnessIsRefused(t *testing.T) {
	aid, sign := witness(t)
	said := "EAAAsomeeventidentifier0123456789ABCDEFGHIJK"
	sig := sign(said)
	if err := VerifyReceipt(aid, said, sig); err != nil {
		t.Fatalf("the genuine receipt did not verify: %v", err)
	}
	if err := VerifyReceipt(otherSpelling(aid), said, sig); err == nil {
		t.Fatal("a receipt verified under a second spelling of its witness")
	}
}

// Two spellings of one witness give one key, and the second is no witness.
func TestAWitnessIsKnownByItsKey(t *testing.T) {
	aid, _ := witness(t)
	if _, ok := WitnessKey(aid); !ok {
		t.Fatal("a canonical witness identifier had no key")
	}
	if _, ok := WitnessKey(otherSpelling(aid)); ok {
		t.Fatal("a second spelling of a witness identifier was read as a witness")
	}
}
