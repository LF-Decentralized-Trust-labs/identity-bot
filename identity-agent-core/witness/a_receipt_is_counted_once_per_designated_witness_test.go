package witness

import "testing"

// Two events with no digest of their own that serialise to the same length are
// two events, not one: neither is given an identifier, so nothing keyed on the
// identifier can cross-wire them.
func TestAnEventWithoutADigestHasNoIdentifier(t *testing.T) {
	a := map[string]interface{}{"t": "icp", "i": "Eaaaa", "s": "0"}
	b := map[string]interface{}{"t": "icp", "i": "Ebbbb", "s": "0"}
	if got := eventSAID(a); got != "" {
		t.Fatalf("an event with no d was given the identifier %q", got)
	}
	if got := eventSAID(b); got != "" {
		t.Fatalf("a same-length event with no d was given the identifier %q", got)
	}
	if got := eventSAID(map[string]interface{}{"d": "EReal"}); got != "EReal" {
		t.Fatalf("an event's own digest was not used: %q", got)
	}
}

// A witness that answers twice advances the count once, and a name nobody
// designated advances it not at all.
func TestAReceiptIsCountedOncePerDesignatedWitness(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	stranger := witnessesOf(1).keys[0]
	icp := inceptionOf(theAID, w.keys, 2)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 2, icp)

	if err := s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp); err != nil {
		t.Fatalf("a designated witness's receipt was refused: %v", err)
	}
	_ = s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp)
	_ = s.receive(said, stranger, "0Bsig", icp)

	f, _ := s.Store.GetFinalization(said)
	if f == nil || f.ReceiptCount != 1 {
		t.Fatalf("one witness answering twice, and one nobody designated, counted %+v, want 1", f)
	}
	if f.State == FinalizeFinalized {
		t.Fatal("the threshold of 2 was met by one witness")
	}
}
