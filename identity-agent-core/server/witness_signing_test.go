package server

import (
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// An agent that has been given key material, which witnessing requires — it
// derives its witnessing key from the same seed as everything else it holds.
func witnessWithSeed(t *testing.T, mark byte) *CoreServer {
	t.Helper()
	s := witnessWithStore(t)
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i) + mark
	}
	if err := secureenclave.StoreRootSeed(s.DataDir, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

// The property that makes a receipt worth anything: somebody who has only the
// witness's identifier — which is written in the key event itself — can check
// the signature. No fetch, no address, nothing that can answer wrongly.
func TestAReceiptChecksOutAgainstTheWitnessIdentifierAlone(t *testing.T) {
	s := witnessWithSeed(t, 1)
	const said = "EEventSAID0123456789ABCDEFGHIJKLMNOPQRSTUVW"

	witnessAID, sig, err := s.signWitnessReceipt(said)
	if err != nil {
		t.Fatalf("could not witness: %v", err)
	}
	if !strings.HasPrefix(witnessAID, "B") {
		t.Fatalf("a witness must be named by a non-transferable identifier, got %q", witnessAID)
	}

	pub, err := iacrypto.KeyFromNonTransferableAID(witnessAID)
	if err != nil {
		t.Fatalf("the witness identifier does not yield a key: %v", err)
	}
	ok, err := login.VerifyString(said, sig, pub)
	if err != nil || !ok {
		t.Fatalf("the receipt does not verify against the identifier that issued it (err=%v)", err)
	}
}

// A receipt for one event must not verify for another, or it attests to nothing
// in particular.
func TestAReceiptDoesNotCoverADifferentEvent(t *testing.T) {
	s := witnessWithSeed(t, 1)
	witnessAID, sig, err := s.signWitnessReceipt("EEventSAID0123456789ABCDEFGHIJKLMNOPQRSTUVW")
	if err != nil {
		t.Fatalf("could not witness: %v", err)
	}
	pub, _ := iacrypto.KeyFromNonTransferableAID(witnessAID)
	ok, _ := login.VerifyString("EOtherEvent456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", sig, pub)
	if ok {
		t.Fatal("a receipt verified against an event it was not issued for")
	}
}

// The witnessing identity has to survive a restart. A witness that renamed
// itself would silently invalidate every receipt it had already issued, and the
// controllers relying on them would have no way to see it happen.
func TestTheWitnessKeepsTheSameIdentityAcrossCalls(t *testing.T) {
	s := witnessWithSeed(t, 1)
	first, _, err := s.signWitnessReceipt("EEventSAID0123456789ABCDEFGHIJKLMNOPQRSTUVW")
	if err != nil {
		t.Fatalf("could not witness: %v", err)
	}
	second, _, err := s.signWitnessReceipt("EAnotherEvent89ABCDEFGHIJKLMNOPQRSTUVWXYZab")
	if err != nil {
		t.Fatalf("could not witness a second time: %v", err)
	}
	if first != second {
		t.Fatalf("the witness changed identity between events: %s then %s", first, second)
	}
}

// Two agents must not witness under the same identifier, or a receipt says
// nothing about which of them saw the event.
func TestTwoAgentsWitnessUnderDifferentIdentifiers(t *testing.T) {
	a, b := witnessWithSeed(t, 1), witnessWithSeed(t, 9)
	const said = "EEventSAID0123456789ABCDEFGHIJKLMNOPQRSTUVW"
	aidA, _, err := a.signWitnessReceipt(said)
	if err != nil {
		t.Fatalf("agent A: %v", err)
	}
	aidB, _, err := b.signWitnessReceipt(said)
	if err != nil {
		t.Fatalf("agent B: %v", err)
	}
	if aidA == aidB {
		t.Fatal("two separate agents witness under the same identifier")
	}
}

// The encoder and decoder are each other's inverse — checked directly, because
// everything above rests on it.
func TestTheWitnessIdentifierRoundTrips(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	aid := iacrypto.NonTransferableAIDQB64(raw)
	if len(aid) != 44 {
		t.Fatalf("identifier is %d characters, want 44: %q", len(aid), aid)
	}
	back, err := iacrypto.KeyFromNonTransferableAID(aid)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(back) != string(raw) {
		t.Fatal("the key does not survive being encoded as an identifier and read back")
	}
}
