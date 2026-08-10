package witness

import (
	"context"
	"testing"

	"identity-agent-core/store"
)

// Adding a contact is the moment the witness pool can grow. These hold the
// rule that decides whether it does: a contact can witness when something of
// theirs is always on to answer, and not otherwise.

// asked records whether a witness request went out, without sending one.
func lifecycleService(t *testing.T) (*Service, *memContacts, *[]string) {
	t.Helper()
	s, mc := testService(t)
	var sent []string
	s.PostEvent = func(ctx context.Context, url string, body []byte) (map[string]interface{}, error) {
		sent = append(sent, url)
		return map[string]interface{}{"status": "ok"}, nil
	}
	return s, mc, &sent
}

func acceptedContact(t *testing.T, s *Service, mc *memContacts, aid, backend string) {
	t.Helper()
	mc.contacts[aid] = store.ContactRecord{
		AID: aid, Status: "accepted", ContactCategory: "general",
		OobiURL: "https://peer.example/public/oobi/" + aid,
	}
	if backend != "" {
		s.RecordContactCapability(aid, backend, "")
	}
}

// A contact whose agent runs on a computer — their own or hosted, it makes no
// difference — can answer when somebody else publishes an event, so it is asked.
func TestAContactWithAnAlwaysOnBackendIsAskedToWitness(t *testing.T) {
	for _, backend := range []string{BackendDesktop, BackendHosted, BackendCommercial} {
		s, mc, sent := lifecycleService(t)
		acceptedContact(t, s, mc, "EPeerWithABackend", backend)

		s.ConsiderContactAsWitness(context.Background(), "EPeerWithABackend")
		if len(*sent) == 0 {
			t.Fatalf("a contact running on %q was never asked to witness", backend)
		}
	}
}

// A contact reachable only on a phone cannot witness: witnessing means being
// there when somebody else's event needs receipting, and a phone is not.
func TestAMobileOnlyContactIsNotAskedToWitness(t *testing.T) {
	s, mc, sent := lifecycleService(t)
	acceptedContact(t, s, mc, "EPeerOnAPhone", BackendMobile)

	s.ConsiderContactAsWitness(context.Background(), "EPeerOnAPhone")
	if len(*sent) != 0 {
		t.Fatal("a contact reachable only on a phone was asked to witness, and could not serve")
	}
}

// A contact that has published nothing about itself is left alone rather than
// guessed at. Assuming it cannot witness would exclude everybody this agent has
// simply not resolved yet; assuming it can would waste the request.
func TestAContactWithNoPublishedBackendIsLeftAlone(t *testing.T) {
	s, mc, sent := lifecycleService(t)
	acceptedContact(t, s, mc, "EPeerWeKnowNothingAbout", "")

	s.ConsiderContactAsWitness(context.Background(), "EPeerWeKnowNothingAbout")
	if len(*sent) != 0 {
		t.Fatal("a contact whose capability is unknown was asked to witness anyway")
	}
}

// A contact that is not accepted is not a relationship yet.
func TestAPendingContactIsNotAskedToWitness(t *testing.T) {
	s, mc, sent := lifecycleService(t)
	mc.contacts["EStillPending"] = store.ContactRecord{AID: "EStillPending", Status: "pending_inbound"}
	s.RecordContactCapability("EStillPending", BackendDesktop, "")

	s.ConsiderContactAsWitness(context.Background(), "EStillPending")
	if len(*sent) != 0 {
		t.Fatal("a contact that has not been accepted was asked to witness")
	}
}

// Already a witness — asking again would enrol nobody and cost a request.
func TestAContactAlreadyWitnessingIsNotAskedAgain(t *testing.T) {
	s, mc, sent := lifecycleService(t)
	acceptedContact(t, s, mc, "EPeerAlreadyWitnessing", BackendDesktop)
	c := mc.contacts["EPeerAlreadyWitnessing"]
	c.IsWitness = true
	mc.contacts["EPeerAlreadyWitnessing"] = c

	s.ConsiderContactAsWitness(context.Background(), "EPeerAlreadyWitnessing")
	if len(*sent) != 0 {
		t.Fatal("a contact that already witnesses was asked again")
	}
}

// What a contact publishes has to survive, or the decision cannot be made later.
func TestAContactsPublishedCapabilityIsRemembered(t *testing.T) {
	s, _ := testService(t)
	s.RecordContactCapability("EPeer", BackendDesktop, "BpeerWitnessKey00000000000000000000000000000")

	meta, err := s.Store.GetContactMeta("EPeer")
	if err != nil || meta == nil {
		t.Fatalf("nothing was recorded about the contact: %v", err)
	}
	if meta.BackendType != BackendDesktop {
		t.Errorf("backend recorded as %q", meta.BackendType)
	}
	if meta.WitnessKey == "" {
		t.Error("the contact's witness key was dropped, so it could never be designated")
	}
}
