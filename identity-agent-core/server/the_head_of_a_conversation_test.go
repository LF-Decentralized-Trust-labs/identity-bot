package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/conversationbundle"
	"identity-agent-core/didcomm"
)

// The Identity Agent answers a conversation's head and count to its owner and
// to the app that keeps it, and to nobody else, and signs the same pair for an
// export (ADR-068).

func aHeadAddon() Addon {
	return Addon{ID: "heads", Name: "heads", ConversationHead: func(_ *CoreServer, id string) (ConversationHead, bool, error) {
		switch id {
		case "kept":
			return ConversationHead{Count: 3, Head: "Ehead3", App: appAID}, true, nil
		case "another-apps":
			return ConversationHead{Count: 1, Head: "Ehead1", App: "Eother"}, true, nil
		case "no-app":
			return ConversationHead{Count: 2, Head: "Ehead2"}, true, nil
		case "empty":
			return ConversationHead{App: appAID}, true, nil
		case "broken":
			return ConversationHead{Count: 2, Head: ""}, true, nil
		}
		return ConversationHead{}, false, nil
	}}
}

func theOwnerAsks(w *anAppWorld, id string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/conversations/"+id+"/head", nil)
	r.RemoteAddr = "127.0.0.1:51000"
	r.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	return rec
}

func theAppAsks(t *testing.T, w *anAppWorld, id string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, w.signedAsTheApp(t, http.MethodGet, "/api/conversations/"+id+"/head", ""))
	return rec
}

func TestTheHeadAndCountAreAnsweredToTheOwnerAndTheAppThatKeepsTheConversation(t *testing.T) {
	onlyAddons(t, aHeadAddon())
	w := newAnAppWorld(t)
	_ = w.cw.s.DataStore.DeleteCredential("Egrant")
	w.enrolApp(t, w.cw.s, []string{CapabilityConversationHeadRead})
	want := `{"conversation":"kept","count":3,"head":"Ehead3"}`
	for who, rec := range map[string]*httptest.ResponseRecorder{"owner": theOwnerAsks(w, "kept"), "app": theAppAsks(t, w, "kept")} {
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != want {
			t.Errorf("%s was answered %d %s, want %s", who, rec.Code, rec.Body, want)
		}
	}
	// A conversation with nothing committed has count 0 and an empty head.
	if rec := theAppAsks(t, w, "empty"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count":0,"head":""`) {
		t.Errorf("an empty conversation was answered %d %s", rec.Code, rec.Body)
	}
	// The owner is told of a conversation no app keeps too.
	if rec := theOwnerAsks(w, "no-app"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Ehead2") {
		t.Errorf("the owner was answered %d %s", rec.Code, rec.Body)
	}
}

// An app is told nothing of a conversation another app keeps, or that no app
// keeps, or that is not there, and in the same words for each: the route does
// not say which conversations exist.
func TestAnAppIsToldNothingOfAConversationItDoesNotKeep(t *testing.T) {
	onlyAddons(t, aHeadAddon())
	w := newAnAppWorld(t)
	_ = w.cw.s.DataStore.DeleteCredential("Egrant")
	w.enrolApp(t, w.cw.s, []string{CapabilityConversationHeadRead})
	var words []string
	for _, id := range []string{"another-apps", "no-app", "nobody-has-this"} {
		rec := theAppAsks(t, w, id)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "Ehead") {
			t.Errorf("%s: an app was answered %d %s", id, rec.Code, rec.Body)
		}
		words = append(words, rec.Body.String())
	}
	if words[0] != words[1] || words[1] != words[2] {
		t.Errorf("the refusals differ, so they tell which conversations exist: %q", words)
	}
	if rec := theOwnerAsks(w, "nobody-has-this"); rec.Code != http.StatusNotFound || rec.Body.String() != words[2] {
		t.Errorf("the owner was answered %d %s for a conversation nobody has", rec.Code, rec.Body)
	}
}

// An app whose grant lacks the capability is refused by the gate, and one that
// has none at all is not read as the owner.
func TestAnAppWithoutTheCapabilityIsRefusedTheHead(t *testing.T) {
	onlyAddons(t, aHeadAddon())
	w := newAnAppWorld(t) // holds agent.message.send and agent.message.read only
	rec := theAppAsks(t, w, "kept")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CapabilityConversationHeadRead) || strings.Contains(rec.Body.String(), "Ehead") {
		t.Fatalf("an app without the capability was answered %d %s", rec.Code, rec.Body)
	}
}

// With no add-on that keeps conversations, every caller is told the same as
// for a conversation that is not there; a head that does not fit its count is
// an error, never an answer.
func TestNoAddOnKeepsConversationsOrReportsABadHead(t *testing.T) {
	onlyAddons(t)
	w := newAnAppWorld(t)
	if rec := theOwnerAsks(w, "kept"); rec.Code != http.StatusNotFound {
		t.Errorf("with no add-on the owner was answered %d %s", rec.Code, rec.Body)
	}
	onlyAddons(t, aHeadAddon())
	if rec := theOwnerAsks(w, "broken"); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "Ehead") {
		t.Errorf("a head that does not fit its count was answered %d %s", rec.Code, rec.Body)
	}
	onlyAddons(t, aHeadAddon(), aHeadAddon())
	if rec := theOwnerAsks(w, "kept"); rec.Code != http.StatusInternalServerError {
		t.Errorf("a conversation two add-ons hold was answered %d %s", rec.Code, rec.Body)
	}
}

// The statement an export carries is the route's pair, signed by the Identity
// Agent, and opens with its messaging keys.
func TestTheHeadStatementIsTheRoutesPairSigned(t *testing.T) {
	onlyAddons(t, aHeadAddon())
	w := newAnAppWorld(t)
	s := w.cw.s
	env, err := s.SignTheHeadOf("kept")
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := s.DataStore.GetIdentity()
	did, err := s.messagingKeysOf(identity.AID)
	if err != nil {
		t.Fatal(err)
	}
	h, err := conversationbundle.OpenHead(did, env)
	if err != nil {
		t.Fatal(err)
	}
	if h.Conversation != "kept" || h.Count != 3 || h.Head != "Ehead3" || h.IATime == "" {
		t.Fatalf("the statement says %+v", h)
	}
	if _, err := s.SignTheHeadOf("nobody-has-this"); err == nil {
		t.Fatal("a statement was signed for a conversation nobody holds")
	}
	// A statement is the Identity Agent's: another's key does not open it.
	other, _ := didcomm.GenerateKeySet("Eother")
	otherDID, _ := other.DID()
	if _, err := conversationbundle.OpenHead(otherDID, env); err == nil {
		t.Fatal("a head statement opened with a key that did not sign it")
	}
}
