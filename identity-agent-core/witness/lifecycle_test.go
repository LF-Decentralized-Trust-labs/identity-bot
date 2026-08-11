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
	// This agent belongs to a person unless a test says otherwise. Peers
	// witness only for their own kind, so every case has to be explicit about
	// which kind is which.
	s.OurEntityType = func() EntityType { return EntityIndividual }
	var sent []string
	s.PostEvent = func(ctx context.Context, url string, body []byte) (map[string]interface{}, error) {
		sent = append(sent, url)
		return map[string]interface{}{"status": "ok"}, nil
	}
	return s, mc, &sent
}

func acceptedContact(t *testing.T, s *Service, mc *memContacts, aid, backend string) {
	t.Helper()
	acceptedContactOfKind(t, s, mc, aid, backend, EntityIndividual)
}

func acceptedContactOfKind(t *testing.T, s *Service, mc *memContacts, aid, backend string, kind EntityType) {
	t.Helper()
	mc.contacts[aid] = store.ContactRecord{
		AID: aid, Status: "accepted", ContactCategory: "general",
		OobiURL: "https://peer.example/public/oobi/" + aid,
	}
	if backend != "" || kind != EntityUnknown {
		s.RecordContactCapability(aid, backend, "", string(kind))
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
	s.RecordContactCapability("EStillPending", BackendDesktop, "", string(EntityIndividual))

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
	s.RecordContactCapability("EPeer", BackendDesktop, "BpeerWitnessKey00000000000000000000000000000",
		string(EntityOrganization))

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
	if meta.EntityType != string(EntityOrganization) {
		t.Errorf("the contact's kind was recorded as %q, so the boundary could not be applied",
			meta.EntityType)
	}
}

// The boundary, as a test, because it is a permanent consequence rather than a
// preference. A witness list is named in the inception event, so it is public
// and cannot be amended away.

// An organization must not witness for a person. It would write that
// organization permanently into the person's founding event, where anyone who
// resolves its witness key can read it — an employer, a clinic, a shelter. The
// person never chose to publish that and cannot unpublish it.
func TestAnOrganizationIsNotAskedToWitnessForAnIndividual(t *testing.T) {
	s, mc, sent := lifecycleService(t) // this agent is an individual
	acceptedContactOfKind(t, s, mc, "EAnOrganization", BackendDesktop, EntityOrganization)

	s.ConsiderContactAsWitness(context.Background(), "EAnOrganization")
	if len(*sent) != 0 {
		t.Fatal("an organization was asked to witness for an individual, which would publish " +
			"that connection permanently in the individual's own inception event")
	}
}

// And the reverse leaks the same fact the other way: an individual named in an
// organization's witness list ties that person to it just as publicly.
func TestAnIndividualIsNotAskedToWitnessForAnOrganization(t *testing.T) {
	s, mc, sent := lifecycleService(t)
	s.OurEntityType = func() EntityType { return EntityOrganization }
	acceptedContactOfKind(t, s, mc, "EAPerson", BackendDesktop, EntityIndividual)

	s.ConsiderContactAsWitness(context.Background(), "EAPerson")
	if len(*sent) != 0 {
		t.Fatal("an individual was asked to witness for an organization")
	}
}

// Same kind is the whole point of peer witnessing, and must still work.
func TestPeersOfTheSameKindStillWitnessForEachOther(t *testing.T) {
	for _, kind := range []EntityType{EntityIndividual, EntityOrganization} {
		s, mc, sent := lifecycleService(t)
		s.OurEntityType = func() EntityType { return kind }
		acceptedContactOfKind(t, s, mc, "EPeerOfTheSameKind", BackendDesktop, kind)

		s.ConsiderContactAsWitness(context.Background(), "EPeerOfTheSameKind")
		if len(*sent) == 0 {
			t.Fatalf("a %s peer was not asked to witness for another %s", kind, kind)
		}
	}
}

// A contact that has not said what it is gets refused rather than guessed at.
// Allowing it wrongly is permanent; refusing it wrongly costs one witness until
// the contact is resolved again.
func TestAContactOfUnknownKindIsNotAskedToWitness(t *testing.T) {
	s, mc, sent := lifecycleService(t)
	acceptedContactOfKind(t, s, mc, "EWhoKnows", BackendDesktop, EntityUnknown)

	s.ConsiderContactAsWitness(context.Background(), "EWhoKnows")
	if len(*sent) != 0 {
		t.Fatal("a contact that never said what kind it is was asked to witness")
	}
}

// An agent that does not yet know what IT is must not enrol peers either —
// during onboarding, before a profile exists.
func TestAnAgentThatDoesNotKnowItsOwnKindEnrolsNoPeers(t *testing.T) {
	s, mc, sent := lifecycleService(t)
	s.OurEntityType = func() EntityType { return EntityUnknown }
	acceptedContactOfKind(t, s, mc, "EAPerson", BackendDesktop, EntityIndividual)

	s.ConsiderContactAsWitness(context.Background(), "EAPerson")
	if len(*sent) != 0 {
		t.Fatal("an agent with no profile enrolled a peer witness")
	}
}

// Witness SERVICES are exempt, and must be: they serve a large population, so
// naming one says almost nothing about its subject. Without this a brand-new
// individual identity could be witnessed by nobody at all, since it has no
// contacts and cannot use an organization.
func TestACommercialWitnessServiceIsNotSubjectToTheBoundary(t *testing.T) {
	if !ContactWitnessAllowedForAID(AidKindRoot, true) {
		t.Fatal("a commercial witness was refused on a root AID")
	}
	// The bootstrap pool is what a fresh individual identity actually gets, and
	// it must survive the boundary.
	got := withBootstrap(nil, 3)
	if len(got) == 0 {
		t.Fatal("a new individual identity was left with no witnesses at all")
	}
	for _, w := range got {
		if !w.Commercial {
			t.Fatalf("%s is not a commercial witness, so it should not be in the pool", w.AID)
		}
	}
}
