package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An introduction that names somebody else records nobody.
//
// The refusal always existed. It ran AFTER the write it was refusing, so the
// stranger was recorded every time — its own comment said it was there to stop
// "an attempt to have us record a stranger under a name we already trust".
//
// That mattered beyond tidiness: on an agent whose owner is named by its
// inception but has no sealed key, the owner's key is resolved from a contact
// record. So a peer this agent already knows could name any address it liked,
// serve back the owner's identifier with its own key, and become the owner for
// every owner-signed request afterwards. DIDComm delivery is public.
func TestAnIntroductionThatNamesSomebodyElseRecordsNothing(t *testing.T) {
	s := serverWithIdentity(t, "EUS")

	// An address that answers as somebody OTHER than whoever sent the envelope.
	const impersonated = "ETHEOWNER"
	oobi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"aid":        impersonated,
			"public_key": "DTheStrangersOwnKey",
			"alias":      "not who sent this",
		})
	}))
	defer oobi.Close()

	body, _ := json.Marshal(map[string]string{"sender_oobi": oobi.URL})
	err := (contactRequest{}).Perform(s, InboundMessage{
		FromAID: "ETHESENDER",
		Body:    body,
	})

	if err == nil {
		t.Fatal("an introduction naming a different identity was accepted")
	}
	if !strings.Contains(err.Error(), impersonated) {
		t.Errorf("the refusal does not say who the address belonged to: %v", err)
	}

	// The point of the test: refused AND not written.
	if c, gerr := s.DataStore.GetContact(impersonated); gerr == nil && c != nil && c.AID != "" {
		t.Fatalf("the stranger was recorded under %s anyway, which is what the "+
			"refusal exists to prevent: %+v", impersonated, c)
	}
	if rec, gerr := s.DataStore.GetContactKEL(impersonated); gerr == nil && rec != nil &&
		rec.CurrentPublicKey != "" {
		t.Fatalf("a key history was recorded for %s anyway: %+v", impersonated, rec)
	}
}
