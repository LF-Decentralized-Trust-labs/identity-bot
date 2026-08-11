package witness

import (
	"context"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// withdrawing sets up an agent that witnesses for a controller it can reach.
func withdrawing(t *testing.T) (*Service, *memContacts, *[]string) {
	t.Helper()
	s, mc := testService(t)
	s.OurWitnessAID = func() (string, error) { return testWitnessAID, nil }
	var posted []string
	s.PostEvent = func(ctx context.Context, url string, body []byte) (map[string]interface{}, error) {
		posted = append(posted, url)
		return map[string]interface{}{"status": "acknowledged"}, nil
	}
	mc.contacts["EController"] = store.ContactRecord{
		AID: "EController", Status: "accepted",
		OobiURL: "https://controller.example/public/oobi/EController",
	}
	if err := s.Store.SaveContactMeta(ContactMeta{
		ContactAID: "EController", BackendType: BackendDesktop, WitnessingFor: true,
	}); err != nil {
		t.Fatal(err)
	}
	return s, mc, &posted
}

// The point of the whole exchange: asking to stop does not stop anything. Until
// the controller rotates, its log still designates this witness and verifiers
// still expect receipts from it.
func TestAskingToStopDoesNotStopWitnessing(t *testing.T) {
	s, _, posted := withdrawing(t)

	if err := s.RequestWithdrawal(context.Background(), "EController", WithdrawalShuttingDown); err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 1 {
		t.Fatalf("the controller was not told: %v", *posted)
	}
	meta, _ := s.Store.GetContactMeta("EController")
	if meta == nil || !meta.WitnessingFor {
		t.Fatal("the witness stopped as soon as it asked, which would leave the controller " +
			"unable to meet its threshold with nothing explaining why")
	}
}

// A witness cannot stand down from something it was never doing.
func TestStandingDownFromSomethingWeDoNotDoIsRefused(t *testing.T) {
	s, mc, _ := withdrawing(t)
	mc.contacts["EStranger"] = store.ContactRecord{AID: "EStranger", Status: "accepted"}

	if err := s.RequestWithdrawal(context.Background(), "EStranger", WithdrawalNoCapacity); err == nil {
		t.Fatal("an agent stood down from an identity it does not witness for")
	}
}

// A confirmation must carry the rotation that cut this witness. Stopping on an
// assurance that cannot be checked is the same failure as stopping early.
func TestAConfirmationWithoutTheRotationIsRefused(t *testing.T) {
	s, _, _ := withdrawing(t)
	key := testWitnessAID

	err := s.ReceiveWithdrawalConfirmation(WithdrawalConfirmation{
		ControllerAID: "EController", WitnessKey: key,
	}, nil)
	if err == nil {
		t.Fatal("a witness stopped on a claim with no evidence behind it")
	}
	if !strings.Contains(err.Error(), "rotation") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// And a rotation that does not actually cut this witness must not be accepted,
// however confidently it is presented.
func TestAConfirmationThatDoesNotCutUsIsRefused(t *testing.T) {
	s, _, _ := withdrawing(t)
	key := testWitnessAID

	stillThere := func(rawB64, witnessKey string) (bool, error) { return true, nil }
	err := s.ReceiveWithdrawalConfirmation(WithdrawalConfirmation{
		ControllerAID: "EController", WitnessKey: key, RotationRawB64: "cm90YXRpb24=",
	}, stillThere)
	if err == nil {
		t.Fatal("a witness stopped while the controller's log still designated it")
	}

	meta, _ := s.Store.GetContactMeta("EController")
	if meta == nil || !meta.WitnessingFor {
		t.Fatal("it stopped anyway")
	}
}

// A confirmation naming somebody else's key is not about us.
func TestAConfirmationForAnotherWitnessIsRefused(t *testing.T) {
	s, _, _ := withdrawing(t)
	cut := func(rawB64, witnessKey string) (bool, error) { return false, nil }

	if err := s.ReceiveWithdrawalConfirmation(WithdrawalConfirmation{
		ControllerAID:  "EController",
		WitnessKey:     "BSomebodyElsesWitnessKey000000000000000000",
		RotationRawB64: "cm90YXRpb24=",
	}, cut); err == nil {
		t.Fatal("a witness stopped on a confirmation that cut a different key")
	}
}

// The ordinary case: proven, so it stops.
func TestAProvenRemovalStopsTheWitnessing(t *testing.T) {
	s, _, _ := withdrawing(t)
	key := testWitnessAID
	cut := func(rawB64, witnessKey string) (bool, error) { return false, nil }

	if err := s.ReceiveWithdrawalConfirmation(WithdrawalConfirmation{
		ControllerAID: "EController", WitnessKey: key, RotationRawB64: "cm90YXRpb24=",
	}, cut); err != nil {
		t.Fatalf("a proven removal was refused: %v", err)
	}
	meta, _ := s.Store.GetContactMeta("EController")
	if meta != nil && meta.WitnessingFor {
		t.Fatal("it kept witnessing after being cut")
	}
}

// A controller receiving a withdrawal must not act on it by itself: removing a
// witness means rotating keys, which is a decision and possibly a ceremony.
func TestReceivingAWithdrawalDoesNotRemoveAnythingByItself(t *testing.T) {
	s, mc := testService(t)
	mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", Status: "accepted", IsWitness: true}
	if err := s.Store.SaveContactMeta(ContactMeta{
		ContactAID: "EWitness", BackendType: BackendDesktop, WitnessKey: "BTheirWitnessKey",
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.ReceiveWithdrawalRequest(WithdrawalRequest{
		WitnessAID: "EWitness", WitnessKey: "BTheirWitnessKey", Reason: WithdrawalShuttingDown,
	}); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Contacts.GetContact("EWitness")
	if c == nil || !c.IsWitness {
		t.Fatal("an inbound request removed a witness on its own; only a rotation can do " +
			"that, and only the controller decides when")
	}
}

// A withdrawal has to say which KEY is standing down. A controller cuts a key,
// not a contact, and the key is not derivable from the identifier.
func TestAWithdrawalMustNameTheWitnessKey(t *testing.T) {
	s, _ := testService(t)
	if err := s.ReceiveWithdrawalRequest(WithdrawalRequest{WitnessAID: "EWitness"}); err == nil {
		t.Fatal("a withdrawal naming no witness key was accepted")
	}
}

// testWitnessAID is a well-shaped non-transferable identifier. Withdrawal cares
// which key is standing down, not what it can sign.
const testWitnessAID = "BMtfjviEMpF2xWVW0CRPKoVPX1mOMzNurvUjD-0RN_Jl"
