package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/endpoint"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// An Identity Agent that signs a fresh challenge with the keys its identifier
// has in force, and what an asker does with the answer (ADR-062, amended
// 2026-11-06).

const (
	proofAgentAID = "EAgentIdentifierForTheProofTests"
	proofAgentURL = "https://agent.example.com"
	proofAgentOrg = "https://agent.example.com:443"
	proofFresh    = "a-fresh-random-challenge-0001"
)

// anAgentHoldingKeys is an Identity Agent reached at proofAgentURL that holds a
// messaging keyset for proofAgentAID, and the key log that commits to it.
func anAgentHoldingKeys(t *testing.T) (*CoreServer, []map[string]interface{}) {
	t.Helper()
	s := agentWithNoIdentity(t)
	s.EndpointService = endpoint.New(nil, 8080)
	s.EndpointService.SetOverrideURL(proofAgentURL)
	s.proofLimiter = newIPRateLimiter(600, time.Minute)
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: proofAgentAID}); err != nil {
		t.Fatal(err)
	}
	ks, err := didcomm.GenerateKeySet(proofAgentAID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.storeKeySetFor(proofAgentAID, ks); err != nil {
		t.Fatal(err)
	}
	dsa, _ := ks.DsaPub.MarshalBinary()
	kem, _ := ks.KemPub.MarshalBinary()
	anchor, err := iacrypto.KeySetAnchor(ks.XPub[:], kem, ks.EdPub, dsa)
	if err != nil {
		t.Fatal(err)
	}
	return s, []map[string]interface{}{{"t": "icp", "i": proofAgentAID, "a": []interface{}{anchor}}}
}

func askForProof(s *CoreServer, origin, challenge string) *httptest.ResponseRecorder {
	q := url.Values{"origin": {origin}, "challenge": {challenge}}
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, remote(http.MethodGet, "/api/identity/proof?"+q.Encode(), ""))
	return w
}

func theProofIn(t *testing.T, w *httptest.ResponseRecorder) *didcomm.KeyProof {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var p didcomm.KeyProof
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestAFreshAnswerFromTheAgentVerifies(t *testing.T) {
	s, log := anAgentHoldingKeys(t)
	w := askForProof(s, proofAgentOrg, proofFresh)
	p := theProofIn(t, w)
	if err := didcomm.CheckKeyProof(p, proofAgentAID, proofAgentOrg, proofFresh, log, "", time.Now()); err != nil {
		t.Fatalf("a fresh answer from the agent was refused: %v", err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("an answer made for one asker may be cached and handed to the next")
	}
}

// The address that relays the identifier's public log and cannot sign: another
// agent, with keys of its own, answering at the address that was dialled.
func TestAnAddressThatRelaysTheLogButCannotSignIsRefused(t *testing.T) {
	_, log := anAgentHoldingKeys(t) // the log the real agent publishes, relayed
	impostor, _ := anAgentHoldingKeys(t)
	p := theProofIn(t, askForProof(impostor, proofAgentOrg, proofFresh))
	if err := didcomm.CheckKeyProof(p, proofAgentAID, proofAgentOrg, proofFresh, log, "", time.Now()); err == nil {
		t.Fatal("an agent whose keys the identifier's log does not commit to was accepted")
	}
}

func TestAReplayedAnswerIsRefused(t *testing.T) {
	s, log := anAgentHoldingKeys(t)
	recorded := theProofIn(t, askForProof(s, proofAgentOrg, "the-challenge-of-last-time-1"))
	if err := didcomm.CheckKeyProof(recorded, proofAgentAID, proofAgentOrg, proofFresh, log, "", time.Now()); err == nil {
		t.Fatal("an answer recorded for another challenge was accepted for a new one")
	}
}

// A proxy that forwards the whole request is refused by the agent, because the
// origin the asker dialled is the proxy's; one that rewrites the origin to the
// agent's gets an answer for an address the asker did not dial.
func TestAProxyThatRelaysTheRequestIsRefused(t *testing.T) {
	s, log := anAgentHoldingKeys(t)
	const proxy = "https://proxy.example.net:443"
	if w := askForProof(s, proxy, proofFresh); w.Code != http.StatusForbidden {
		t.Fatalf("the agent signed for an address that is not its own: %d", w.Code)
	}
	rewritten := theProofIn(t, askForProof(s, proofAgentOrg, proofFresh))
	if err := didcomm.CheckKeyProof(rewritten, proofAgentAID, proxy, proofFresh, log, "", time.Now()); err == nil {
		t.Fatal("an answer for the agent's own address was accepted at the proxy's")
	}
}

func TestOnlyWhatItCanSignIsAnswered(t *testing.T) {
	s, _ := anAgentHoldingKeys(t)
	if w := askForProof(s, proofAgentOrg, "short"); w.Code != http.StatusBadRequest {
		t.Errorf("a short challenge was answered %d", w.Code)
	}
	if w := askForProof(s, "not an origin", proofFresh); w.Code != http.StatusBadRequest {
		t.Errorf("a malformed origin was answered %d", w.Code)
	}
	q := url.Values{"origin": {proofAgentOrg}, "challenge": {proofFresh}, "aid": {"ENotOneOfOurs"}}
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, remote(http.MethodGet, "/api/identity/proof?"+q.Encode(), ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("an identifier this agent holds no keys for was answered %d", w.Code)
	}
	if has, _ := s.hasKeySet("ENotOneOfOurs"); has {
		t.Error("asking made this agent mint keys")
	}
}

// A new agent has no keyset until something needs one, yet is asked about its
// own identifier first; it answers rather than 404ing, as handleGetDIDCommDID does.
func TestANewAgentAnswersForItsOwnIdentifier(t *testing.T) {
	s := agentWithNoIdentity(t)
	s.EndpointService = endpoint.New(nil, 8080)
	s.EndpointService.SetOverrideURL(proofAgentURL)
	s.proofLimiter = newIPRateLimiter(600, time.Minute)
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: proofAgentAID}); err != nil {
		t.Fatal(err)
	}
	if has, _ := s.hasKeySet(proofAgentAID); has {
		t.Fatal("the test needs an agent with no keyset yet")
	}
	p := theProofIn(t, askForProof(s, proofAgentOrg, proofFresh))
	if p.DID.AID != proofAgentAID {
		t.Fatalf("answered for %q", p.DID.AID)
	}
}
