package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// An app asking the witnesses a key log names needs their addresses from this
// computer's own core. A key the core cannot place is left out, and a
// stranger's introduction is never turned into an address.
func TestWitnessAddressesAreReadFromWhatTheCoreHolds(t *testing.T) {
	s, mc := testService(t)
	key := func() string {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return iacrypto.NonTransferableAIDQB64(pub)
	}
	known, stranger, unplaced := key(), key(), key()
	mc.contacts["EKnown"] = store.ContactRecord{AID: "EKnown", OobiURL: "https://w1.test/public/oobi/EKnown", IsWitness: true}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EKnown", WitnessKey: known})
	mc.contacts["EStranger"] = store.ContactRecord{AID: "EStranger", OobiURL: "https://evil.test",
		ContactSource: ContactSourceInbound, Status: "pending_inbound"}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EStranger", WitnessKey: stranger})

	got := s.WitnessAddressesFor([]string{known, stranger, unplaced})
	if got[known] != "https://w1.test" {
		t.Fatalf("the contact's witness was placed at %q", got[known])
	}
	if _, ok := got[stranger]; ok {
		t.Fatal("a stranger's introduction was given an address")
	}
	if _, ok := got[unplaced]; ok || len(got) != 1 {
		t.Fatalf("a key nobody holds an address for was placed: %v", got)
	}
}
