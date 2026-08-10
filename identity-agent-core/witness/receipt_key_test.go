package witness

import (
	"strings"
	"testing"
)

// A witness key must be non-transferable, because a receipt is checked against
// the witness identifier itself. Anything else means resolving a key log first.
func TestTheWitnessKeyIsNonTransferable(t *testing.T) {
	s, _ := testService(t)
	s.DataDir = t.TempDir()

	aid, _, err := s.WitnessKey()
	if err != nil {
		t.Fatalf("this agent could not produce a witness key: %v", err)
	}
	if !strings.HasPrefix(aid, "B") || len(aid) != 44 {
		t.Fatalf("the witness identifier %q is not a non-transferable Ed25519 key", aid)
	}
}

// A receipt this agent issues must verify against the identifier it issued it
// under — the property the previous hex stub did not have, since no key was
// involved and anybody could reproduce the value.
func TestAReceiptThisAgentIssuesVerifiesAgainstIt(t *testing.T) {
	s, _ := testService(t)
	s.DataDir = t.TempDir()

	const said = "EAAAsomeeventidentifier0123456789ABCDEFGHIJK"
	aid, sig, err := s.SignReceipt(said)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(aid, said, sig); err != nil {
		t.Fatalf("this agent's own receipt does not verify: %v", err)
	}

	// And it covers that event only.
	if err := VerifyReceipt(aid, "EBBBadifferentevententirely0123456789ABCDE", sig); err == nil {
		t.Fatal("the receipt verified against an event it was not issued for")
	}
}

// A witness whose key is unknown cannot be designated. Designation is written
// into an inception event and is therefore permanent, so naming an observer
// whose receipts can never be checked is a mistake with no way back.
func TestAWitnessWithNoPublishedKeyIsNotDesignated(t *testing.T) {
	keys, toad := DesignatableWitnesses([]witnessTarget{
		{AID: "EsomeContactWithNoWitnessKeyPublished012345", URL: "https://example.test"},
	})
	if len(keys) != 0 || toad != 0 {
		t.Fatalf("a witness with no published key was designated: %v toad=%d", keys, toad)
	}
}

// With keys known, designation produces a majority threshold.
func TestDesignationRequiresAMajority(t *testing.T) {
	keys, toad := DesignatableWitnesses([]witnessTarget{
		{AID: "E1", WitnessKey: "B1"},
		{AID: "E2", WitnessKey: "B2"},
		{AID: "E3", WitnessKey: "B3"},
	})
	if len(keys) != 3 {
		t.Fatalf("expected three designated witnesses, got %v", keys)
	}
	if toad != 2 {
		t.Fatalf("threshold is %d; a majority of three is 2, so a single dishonest or "+
			"unavailable witness can neither stall nor corroborate alone", toad)
	}
}
