package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A computer connecting to an Identity Agent at an address checks that what
// answers there holds the keys of the identity it names (ADR-062).

// theHostOfAnAgent serves an agent's proof route and the key history it
// publishes, on a real local address, and says what origin that is.
func theHostOfAnAgent(t *testing.T, agent *CoreServer, publish func() []map[string]interface{}) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/api/identity/proof", agent.buildRouter())
	mux.HandleFunc("/public/oobi/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"kel": publish()})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	agent.EndpointService.SetOverrideURL(srv.URL)
	return srv.URL
}

func askWhoIsAt(t *testing.T, asker *CoreServer, address, aid string) verifyIdentityResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"address": address, "aid": aid})
	req := httptest.NewRequest(http.MethodPost, "/api/verify/agent-at-address", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	asker.handleVerifyAnAgentAtAnAddress(rec, req)
	var out verifyIdentityResponse
	_ = json.NewDecoder(rec.Body).Decode(&out)
	return out
}

func theAsker(t *testing.T) *CoreServer {
	t.Helper()
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1") // the agents here are on this machine
	a := agentWithNoIdentity(t)
	a.KeriDriver = acceptingKELDriver(t)
	return a
}

func TestAnAgentThatHoldsTheKeysItsLogCommitsToIsProved(t *testing.T) {
	agent, _ := anAgentHoldingKeys(t)
	ks, _ := agent.keySetFor(proofAgentAID)
	kel := inceptionCommittingTo(t, proofAgentAID, ks)
	// the engine's own view of the log is the bytes it was verified by; the
	// agent publishes the plain events
	plain := kel // records carrying each event as text, as an agent publishes them
	origin := theHostOfAnAgent(t, agent, func() []map[string]interface{} { return plain })
	asker := theAsker(t)
	out := askWhoIsAt(t, asker, origin, "")
	if !out.Verified || out.AID != proofAgentAID || out.PublicKey == "" {
		t.Fatalf("an agent holding its identifier's keys was not proved: %+v", out)
	}
	// a later launch names the identifier it remembered
	if out := askWhoIsAt(t, asker, origin, proofAgentAID); !out.Verified {
		t.Fatalf("the remembered identifier was refused: %+v", out)
	}
	// and one it did not remember is refused: the address answers for another
	if out := askWhoIsAt(t, asker, origin, "ESomebodyElse"); out.Verified {
		t.Fatal("an address that answers for another identifier was accepted")
	}
}

// The address that copies the log and cannot sign: any host can replay a
// public key history, which is all the old check read.
func TestAHostThatReplaysTheLogButHoldsOtherKeysIsNotProved(t *testing.T) {
	real, _ := anAgentHoldingKeys(t)
	realKeys, _ := real.keySetFor(proofAgentAID)
	published := inceptionCommittingTo(t, proofAgentAID, realKeys)
	plain := published

	impostor, _ := anAgentHoldingKeys(t) // same identifier, its own keys
	origin := theHostOfAnAgent(t, impostor, func() []map[string]interface{} { return plain })
	out := askWhoIsAt(t, theAsker(t), origin, "")
	if out.Verified {
		t.Fatal("a host that replayed the public log and signed with other keys was proved")
	}
	if out.Why == "" || out.Kind != KindDifferent {
		t.Errorf("a host with other keys must be reported as a different one with a reason: %+v", out)
	}
}

func TestSomethingThatIsNotAnAgentIsNotProved(t *testing.T) {
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	out := askWhoIsAt(t, theAsker(t), other.URL, "")
	if out.Verified {
		t.Fatal("something with no proof route was accepted")
	}
	if out.Kind != KindDifferent {
		t.Errorf("something else answering was reported as %q", out.Kind)
	}
}

func TestNothingAnsweringIsNotTheSameAsSomethingElseAnswering(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	address := gone.URL
	gone.Close()
	out := askWhoIsAt(t, theAsker(t), address, "")
	if out.Verified || out.Kind != KindNoAnswer {
		t.Fatalf("an address nothing answers at: %+v", out)
	}
}

// A computer that is only the front end for an agent kept elsewhere still makes
// this check: it is how it notices, on every launch, that something else now
// answers where its agent was. Refused by its own core, it would be unable to.
func TestAFrontEndCoreStillChecksWhoIsAtTheAddress(t *testing.T) {
	if _, ok := whatAFrontEndAnswersFor["POST /api/verify/agent-at-address"]; !ok {
		t.Fatal("a front end refuses to check who is at the address it fronts for")
	}
}

// A host that answers the proof and then will not show its history has not "not
// answered": reporting it so would let a swapped agent look like a dropped
// network, and the app would carry on.
func TestAHostThatAnswersTheProofButHidesItsHistoryIsADifferentOne(t *testing.T) {
	agent, _ := anAgentHoldingKeys(t)
	origin := theHostOfAnAgent(t, agent, func() []map[string]interface{} { return nil })
	out := askWhoIsAt(t, theAsker(t), origin, "")
	if out.Verified || out.Kind != KindDifferent {
		t.Fatalf("a host answering the proof with no history behind it was reported %+v", out)
	}
}
