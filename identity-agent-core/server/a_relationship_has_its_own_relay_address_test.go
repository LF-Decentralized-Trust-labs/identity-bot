package server

import (
	"context"

	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/keriengine"
	"identity-agent-core/relay/relaytest"
	"identity-agent-core/store"
)

// privateRelayWithEngine is a core at a private relay that can mint pairwise
// identifiers, with the relay up.
func privateRelayWithEngine(t *testing.T) (*CoreServer, *relaytest.Relay, string) {
	t.Helper()
	s, rl, _, cancel := relayWorld(t, relayproto.ModePrivate)
	t.Cleanup(cancel)
	eng := keriengine.New()
	if err := eng.Start(); err != nil {
		t.Skipf("KERI engine unavailable: %v", err)
	}
	s.KeriDriver = eng
	s.engineSigns()
	go s.startRelay()
	t.Cleanup(s.Stop)
	return s, rl, s.waitForRelay(t)
}

func addressOf(t *testing.T, oobi, aid string) string {
	t.Helper()
	suffix := "/public/oobi/" + aid
	if !strings.HasSuffix(oobi, suffix) {
		t.Fatalf("OOBI %q is not at %s", oobi, suffix)
	}
	return strings.TrimSuffix(oobi, suffix)
}

// Two relationships are given different addresses, and each one's OOBI names
// its own (ADR-048 §6, ADR-036).
func TestTwoRelationshipsAreGivenDifferentRelayAddresses(t *testing.T) {
	s, rl, shared := privateRelayWithEngine(t)

	aidA, oobiA, _, err := s.mintPairwise("a")
	if err != nil {
		t.Fatal(err)
	}
	aidB, oobiB, _, err := s.mintPairwise("b")
	if err != nil {
		t.Fatal(err)
	}
	a, b := addressOf(t, oobiA, aidA), addressOf(t, oobiB, aidB)
	if a == b {
		t.Fatalf("two relationships were handed the same address, %s", a)
	}
	if a == shared || b == shared {
		t.Fatalf("a relationship was handed the shared address %s (%s, %s)", shared, a, b)
	}
	// Each address is the one made for that relationship, and answers it.
	for _, c := range []struct{ addr, aid string }{{a, aidA}, {b, aidB}} {
		code, body := through(t, rl.Caller(), "GET", c.addr+"/public/oobi/"+c.aid, "")
		if code != http.StatusOK || !strings.Contains(body, c.aid) {
			t.Errorf("%s does not answer for its relationship: %d %s", c.addr, code, body)
		}
	}
	// And the label of one is not derived from the other or from the identifier.
	la, lb := a[strings.LastIndex(a, "/")+1:], b[strings.LastIndex(b, "/")+1:]
	if strings.Contains(la, aidA[1:9]) || strings.Contains(lb, aidB[1:9]) {
		t.Errorf("an address label carries part of its identifier: %s %s", la, lb)
	}
}

// Ending a relationship releases its address: the relay no longer holds it and
// it answers nothing.
func TestEndingARelationshipReleasesItsAddress(t *testing.T) {
	s, rl, _ := privateRelayWithEngine(t)

	aid, oobi, _, idx, err := s.mintPairwiseIn("contacts", "ending")
	if err != nil {
		t.Fatal(err)
	}
	addr := addressOf(t, oobi, aid)
	label := addr[strings.LastIndex(addr, "/")+1:]
	if !rl.Holds(label) {
		t.Fatal("the relay does not hold the address it just made")
	}
	if err := s.DataStore.SaveContact(store.ContactRecord{AID: "EContact", Alias: "x", RelationshipAID: aid,
		RelationshipIndex: idx}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/contacts/EContact", nil)
	req = withURLParam(req, "aid", "EContact")
	rec := httptest.NewRecorder()
	s.handleDeleteContact(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deleting the contact: %d %s", rec.Code, rec.Body)
	}

	deadline := time.Now().Add(5 * time.Second)
	for rl.Holds(label) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rl.Holds(label) {
		t.Error("the relay still holds the address of an ended relationship")
	}
	if a := s.currentRelay().Lookup(label); a != nil {
		t.Error("the Identity Agent still answers on the address of an ended relationship")
	}
	if a := s.currentRelay().AddressFor(aid); a != nil {
		t.Error("the Identity Agent still lists an address for an ended relationship")
	}
}

// An address that could not be given back at once stops answering anyway, and
// is given back on the next session.
func TestAnAddressNotGivenBackAtOnceIsGivenBackLater(t *testing.T) {
	s, rl, _ := privateRelayWithEngine(t)
	aid, oobi, _, err := s.mintPairwise("later")
	if err != nil {
		t.Fatal(err)
	}
	addr := addressOf(t, oobi, aid)
	label := addr[strings.LastIndex(addr, "/")+1:]

	rl.Drop(s.currentRelay().Config().EnrollmentAID) // the session is gone
	deadline := time.Now().Add(5 * time.Second)
	for s.currentRelay().GetStatus().Active && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := s.currentRelay().ReleaseFor(s.backgroundContext(), aid); err == nil {
		t.Log("the session came back before the release; the later path is not exercised")
	}
	if s.currentRelay().Lookup(label) != nil {
		t.Error("an ended relationship's address still answers")
	}
	deadline = time.Now().Add(15 * time.Second)
	for rl.Holds(label) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if rl.Holds(label) {
		t.Error("the address of an ended relationship was never given back")
	}
}

// The identifiers the relay knows this Identity Agent by get no address of
// their own, and a public relay keeps its one address.
func TestAnEnrolmentIdentifierGetsNoAddressOfItsOwn(t *testing.T) {
	s, _, shared := privateRelayWithEngine(t)
	if got := s.addressForNewRelationship(privateRelay.pool, "Eenrol"); got != s.EndpointService.CurrentURL() {
		t.Errorf("an enrolment identifier was given its own address: %s", got)
	}
	if s.currentRelay().AddressFor("Eenrol") != nil {
		t.Error("an address was made for an enrolment identifier")
	}
	_ = shared
}

func withURLParam(r *http.Request, k, v string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(k, v)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
