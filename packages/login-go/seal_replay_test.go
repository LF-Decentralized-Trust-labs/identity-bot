package login

import (
	"bytes"
	"encoding/json"
	"testing"
)

// A relay that respells epk's unused bits sends the same point under a new
// spelling. Go's lenient decoder reads all four spellings as one key, which
// let one call be replayed past a replay memory keyed on the text and answered
// twice under one AES-GCM key and nonce. The call must be refused outright.
func TestACallWithItsEphemeralKeyRespelledIsNotOpened(t *testing.T) {
	k, _ := SealKeyFromSeed(sha256Sum("replay"))
	outer, _, err := SealRequest("Erid", k.Public(), []byte("call"))
	if err != nil {
		t.Fatal(err)
	}
	var o map[string]string
	_ = json.Unmarshal(outer, &o)
	last := o["epk"][len(o["epk"])-1]
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	respelled := 0
	for i := 0; i < len(alphabet); i++ {
		c := alphabet[i]
		if c == last {
			continue
		}
		a, errA := b64.DecodeString(o["epk"][:len(o["epk"])-1] + string(c))
		b, _ := b64.DecodeString(o["epk"])
		if errA != nil || !bytes.Equal(a, b) {
			continue // a different point, not a respelling
		}
		respelled++
		raw, _ := json.Marshal(map[string]any{"v": 1, "epk": o["epk"][:len(o["epk"])-1] + string(c), "ct": o["ct"]})
		if _, _, err := k.OpenRequest("Erid", raw); err != ErrSealed {
			t.Fatalf("a respelled epk %q was opened: %v", c, err)
		}
	}
	if respelled != 3 {
		t.Fatalf("expected 3 respellings of the same point, found %d", respelled)
	}
	if _, _, err := k.OpenRequest("Erid", outer); err != nil {
		t.Fatal("the honest spelling was refused")
	}
}

func TestTheReplayKeyIsTheDecodedPoint(t *testing.T) {
	k, _ := SealKeyFromSeed(sha256Sum("replay2"))
	outer, _, _ := SealRequest("Erid", k.Public(), []byte("call"))
	_, r1, err := k.OpenRequest("Erid", outer)
	if err != nil {
		t.Fatal(err)
	}
	_, r2, _ := k.OpenRequest("Erid", outer)
	if r1.Ephemeral() != r2.Ephemeral() || len(r1.Ephemeral()) != 65 {
		t.Fatal("one call's replay key is not its 65 decoded bytes")
	}
	other, _, _ := SealRequest("Erid", k.Public(), []byte("call"))
	_, r3, _ := k.OpenRequest("Erid", other)
	if r3.Ephemeral() == r1.Ephemeral() {
		t.Fatal("two calls share a replay key")
	}
}

// Two answers to one call (a replay that got past, or a restart that forgot)
// never share an AES-GCM key and nonce: the back end's own n is in the key.
func TestTwoAnswersToOneCallAreSealedUnderDifferentKeys(t *testing.T) {
	k, _ := SealKeyFromSeed(sha256Sum("answers"))
	outer, front, _ := SealRequest("Erid", k.Public(), []byte("call"))
	_, back, _ := k.OpenRequest("Erid", outer)
	a, _ := back.Seal([]byte("same answer"))
	b, _ := back.Seal([]byte("same answer"))
	var oa, ob outerAnswer
	_ = json.Unmarshal(a, &oa)
	_ = json.Unmarshal(b, &ob)
	if oa.N == ob.N || oa.Ct == ob.Ct {
		t.Fatal("two answers to one call share n or ciphertext")
	}
	for _, x := range [][]byte{a, b} {
		if got, err := front.Open(x); err != nil || string(got) != "same answer" {
			t.Fatalf("an answer did not open: %v", err)
		}
	}
	// n is bound: an answer with another call's n or none opens nothing.
	oa.N = ob.N
	swapped, _ := json.Marshal(oa)
	if _, err := front.Open(swapped); err != ErrSealed {
		t.Fatal("an answer with another answer's n opened")
	}
}

// A padded message that declares more content than SealMax is refused even when
// its size is exactly the bucket that content would need and the rest is zeros.
func TestAMessageDeclaringMoreThanTheMostIsRefused(t *testing.T) {
	n := SealMax + 1
	want := SealBucket
	for want < n+4 {
		want *= 2
	}
	p := make([]byte, want)
	p[0], p[1], p[2], p[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	if _, err := unpad(p); err == nil {
		t.Fatal("a message declaring more than SealMax was accepted")
	}
}
