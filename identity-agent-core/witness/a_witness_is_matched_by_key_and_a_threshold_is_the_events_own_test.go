package witness

import (
	"context"
	"encoding/base64"
	"testing"
)

// A witness is matched by the key it is made of, wherever the service decides
// who a receipt is from, as the count does. A name that is no witness key is
// nobody's receipt, even where a log lists that very string.
func TestAReceiptFromANameThatIsNoWitnessKeyIsRefused(t *testing.T) {
	s, mc := testService(t)
	w := witnessesOf(1)
	const notAKey = "BNotAWitnessKey0123456789ABCDEFGHIJKLMNOPQR"
	icp := inceptionOf(theAID, []string{w.keys[0], notAKey}, 1)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 1, icp)

	if err := s.receive(said, notAKey, "0Bsig", icp); err == nil {
		t.Fatal("a receipt was taken from a name that is no witness key")
	}
	if held, _ := mc.GetWitnessReceipts(said); len(held) != 0 {
		t.Fatalf("a receipt from a name that is no witness key was kept: %+v", held)
	}
	if err := s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp); err != nil {
		t.Fatalf("the designated witness's receipt was refused: %v", err)
	}
}

// BringUpToDate starts each older event's finalisation at the threshold that
// event's own place in the log asked, not the one in force now.
func TestBringUpToDateFinalisesAnOlderEventAtItsOwnThreshold(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 3)
	rot := rotationOf(theAID, 1, w.keys[2:], nil, 1)
	var log []SignedEvent
	for _, raw := range [][]byte{icp, rot} {
		log = append(log, SignedEvent{RawBytesB64: base64.StdEncoding.EncodeToString(raw), CesrSignature: "0Bsig"})
	}
	s.KeyLogOf = keyLog(theAID, icp, rot)
	s.FetchTip = func(context.Context, string) (TipAnswer, error) { return TipAnswer{}, context.Canceled }

	// Today's threshold, 1, is what the caller holds; the inception asked 3.
	s.BringUpToDate(context.Background(), theAID, log, w.keys, 1)

	for _, c := range []struct {
		raw  []byte
		want int
	}{{icp, 3}, {rot, 1}} {
		f, _ := s.Store.GetFinalization(saidOf(c.raw))
		if f == nil || f.Threshold != c.want {
			t.Fatalf("event %s: finalisation %+v, want a threshold of %d", saidOf(c.raw), f, c.want)
		}
	}
}
