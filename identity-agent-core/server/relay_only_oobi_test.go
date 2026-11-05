package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/store"
)

// An OOBI that is handed out names a relay address and never this agent's
// direct address (ADR-048 §6), and never the root identifier, which identifies
// a person in every relationship they have (ADR-036). Personal data is not in
// an OOBI at all: it reaches a counterparty only through an exchange the
// holder approved (ADR-009, Layer 2).

const rootAIDForOobiTests = "ERootIdentifierOfThePersonWhoOwnsThisAgent0000"

func ownerGet(s *CoreServer, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	return w
}

func strangerGet(s *CoreServer, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "198.51.100.7:4000"
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	return w
}

// a core with a root identity and a profile full of personal data.
func ownerWithRootAndProfile(t *testing.T, s *CoreServer) {
	t.Helper()
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: rootAIDForOobiTests, PublicKey: "DRootPublicKeyForOobiTests"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveProfile(store.ProfileData{
		FullName: "Ada Lovelace", Email: "ada@example.test", Tel: "+15550100", Photo: "PHOTOBYTES",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAnOobiIsNotMadeWhenThereIsNoRelayAddress(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)

	w := ownerGet(s, "/api/oobi")
	if w.Code != http.StatusConflict {
		t.Fatalf("an OOBI was made with no relay address to name: %d %s", w.Code, w.Body)
	}
	for _, leak := range []string{rootAIDForOobiTests, "127.0.0.1", "example.com", "localhost", "/public/oobi/"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("the refusal handed out %q: %s", leak, w.Body)
		}
	}
}

func TestAnOobiNamesOnlyTheRelayAddressAndAPairwiseIdentifier(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	s.KeriDriver = startedEngine(t)
	s.engineSigns()
	ownerWithRootAndProfile(t, s)
	go s.startRelay()
	defer s.Stop()
	relayURL := s.waitForRelay(t)

	w := ownerGet(s, "/api/oobi?action=add_contact")
	if w.Code != http.StatusOK {
		t.Fatalf("no OOBI was made: %d %s", w.Code, w.Body)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	oobi, _ := got["oobi_url"].(string)
	if !strings.HasPrefix(oobi, strings.TrimRight(relayURL, "/")+"/public/oobi/") {
		t.Errorf("the OOBI does not name the relay address %s: %s", relayURL, oobi)
	}
	if aid, _ := got["aid"].(string); aid == "" || aid == rootAIDForOobiTests {
		t.Errorf("the OOBI names %q, not a pairwise identifier made for this counterparty", aid)
	}
	body := w.Body.String()
	for _, leak := range []string{rootAIDForOobiTests, "DRootPublicKeyForOobiTests", ":5050", "ada@example.test", "Ada"} {
		if strings.Contains(body, leak) {
			t.Errorf("the OOBI response handed out %q: %s", leak, body)
		}
	}
	for _, field := range []string{"base_url", "endpoint_url", "public_key", "tunnel_provider"} {
		if _, ok := got[field]; ok {
			t.Errorf("the OOBI response still carries %q, which is a direct address or the root key", field)
		}
	}
}

func TestTheRootIdentifiersOobiIsServedOnlyToItsOwner(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)
	path := "/public/oobi/" + rootAIDForOobiTests

	if w := strangerGet(s, path); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "DRootPublicKeyForOobiTests") {
		t.Errorf("the root identifier was handed to a counterparty: %d %s", w.Code, w.Body)
	}
	// Through a relay at an address it cannot place too. (A public address the
	// owner published serves it: TestAPublicAddressServesTheRootIdentity.)
	for _, mode := range []relayproto.Mode{relayproto.ModePrivate} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(relayproto.ContextWithPreamble(req.Context(),
			relayproto.Preamble{Allocation: "acme", Mode: mode, Host: "acme.relay.test"}))
		w := httptest.NewRecorder()
		s.buildRouter().ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("the root identifier was handed out through a %v relay address: %d %s", mode, w.Code, w.Body)
		}
	}
	if w := ownerGet(s, path); w.Code != http.StatusOK {
		t.Errorf("the owner at this computer cannot read their own OOBI: %d %s", w.Code, w.Body)
	}
}

// Serving an OOBI discloses no personal data to whoever fetches it. The route
// carries no proof of who is asking, so there is nobody it could know consented;
// a counterparty receives a profile through an exchange the holder approved.
func TestServingAnOobiDisclosesNoPersonalData(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)
	registerPairwiseKEL("EPairwiseForOobiPersonalDataTest", []map[string]interface{}{{"t": "icp"}})

	for name, w := range map[string]*httptest.ResponseRecorder{
		"the owner reading the root OOBI":    ownerGet(s, "/public/oobi/"+rootAIDForOobiTests),
		"a stranger reading a pairwise OOBI": strangerGet(s, "/public/oobi/EPairwiseForOobiPersonalDataTest"),
	} {
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		for _, personal := range []string{"Ada", "Lovelace", "ada@example.test", "+15550100", "PHOTOBYTES", "jcard"} {
			if strings.Contains(w.Body.String(), personal) {
				t.Errorf("%s: the response disclosed %q: %s", name, personal, w.Body)
			}
		}
	}
}

// A pairwise identifier's OOBI names no direct address: with no relay address
// it names none, and with one it names that.
func TestAPairwiseOobiNamesNoDirectAddress(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)
	registerPairwiseKEL("EPairwiseForOobiAddressTest", []map[string]interface{}{{"t": "icp"}})

	req := httptest.NewRequest(http.MethodGet, "/public/oobi/EPairwiseForOobiAddressTest", nil)
	req.RemoteAddr = "198.51.100.7:4000"
	req.Host = "direct.agent.example:8443"
	req.Header.Set("X-Forwarded-Host", "direct.agent.example")
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "direct.agent.example") || strings.Contains(w.Body.String(), "\"oobi\"") {
		t.Errorf("a pairwise OOBI named a direct address: %s", w.Body)
	}
}
