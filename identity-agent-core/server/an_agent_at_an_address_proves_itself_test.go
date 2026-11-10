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

func askWhoIsAtKnowing(t *testing.T, asker *CoreServer, address, aid string, seq int64, key string) verifyIdentityResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"address": address, "aid": aid, "known_sequence": seq, "known_key": key})
	req := httptest.NewRequest(http.MethodPost, "/api/verify/agent-at-address", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	asker.handleVerifyAnAgentAtAnAddress(rec, req)
	var out verifyIdentityResponse
	_ = json.NewDecoder(rec.Body).Decode(&out)
	return out
}

// Plain http is believed only where nobody is on the path: this computer. To any
// other host it is refused without dialling, whatever the host would answer.
func TestPlainHttpToAnotherHostIsRefusedWithoutDialling(t *testing.T) {
	asker := theAsker(t)
	for _, address := range []string{
		"http://192.0.2.7:8080", "http://203.0.113.9", "http://box.example.com:5151",
		"http://10.0.0.5:5151", "http://127.evil.example.com:80", "HTTP://Box.Example.com",
	} {
		out := askWhoIsAt(t, asker, address, "")
		if out.Verified || out.Kind != KindNotSecure {
			t.Errorf("%s: plain http to another host was not refused as not secure: %+v", address, out)
		}
	}
	// https is not refused for its scheme (here nothing answers), and http to
	// this computer is asked, not refused.
	if out := askWhoIsAt(t, asker, "https://192.0.2.7:8443", ""); out.Kind == KindNotSecure {
		t.Errorf("https was refused as not secure: %+v", out)
	}
	for _, address := range []string{"http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1"} {
		if out := askWhoIsAt(t, asker, address, ""); out.Kind == KindNotSecure {
			t.Errorf("%s: http to this computer was refused as not secure", address)
		}
	}
}

// An identifier's log only moves forward: a host showing a history that ends
// before the last one proved, or ends at the same event with another key, is
// not the agent as it stands.
func TestAHistoryThatGoesBackwardsIsRefused(t *testing.T) {
	agent, _ := anAgentHoldingKeys(t)
	ks, _ := agent.keySetFor(proofAgentAID)
	plain := inceptionCommittingTo(t, proofAgentAID, ks)
	origin := theHostOfAnAgent(t, agent, func() []map[string]interface{} { return plain })
	asker := theAsker(t)

	first := askWhoIsAt(t, asker, origin, "")
	if !first.Verified || first.Sequence == nil || *first.Sequence != 0 {
		t.Fatalf("the first proof did not say the sequence it proved: %+v", first)
	}
	if out := askWhoIsAtKnowing(t, asker, origin, proofAgentAID, 0, first.PublicKey); !out.Verified {
		t.Fatalf("the same state was refused: %+v", out)
	}
	if out := askWhoIsAtKnowing(t, asker, origin, proofAgentAID, 3, first.PublicKey); out.Verified || out.Kind != KindDifferent {
		t.Fatalf("a history that ends at 0 after 3 was proved: %+v", out)
	}
	if out := askWhoIsAtKnowing(t, asker, origin, proofAgentAID, 0, "DADifferentKeyThanTheOneInForce"); out.Verified {
		t.Fatalf("the same event with another key was proved: %+v", out)
	}
	if out := askWhoIsAtKnowing(t, asker, origin, proofAgentAID, -1+0, first.PublicKey); !out.Verified {
		t.Fatalf("a state older than the log was refused: %+v", out)
	}
}

// A host that ignores which identifier was asked for and proves another one,
// fully and correctly, is still not the identity this computer was connected to:
// the core compares what was proved with what it asked for, whatever the far
// side's own route would have refused.
func TestAHostThatProvesAnotherIdentityThanTheOneAskedForIsADifferentOne(t *testing.T) {
	agent, _ := anAgentHoldingKeys(t)
	ks, _ := agent.keySetFor(proofAgentAID)
	plain := inceptionCommittingTo(t, proofAgentAID, ks)
	router := agent.buildRouter()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/identity/proof", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		q.Del("aid") // answers for itself whoever was asked for
		r.URL.RawQuery = q.Encode()
		router.ServeHTTP(w, r)
	})
	mux.HandleFunc("/public/oobi/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"kel": plain})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	agent.EndpointService.SetOverrideURL(srv.URL)

	asker := theAsker(t)
	if out := askWhoIsAt(t, asker, srv.URL, ""); !out.Verified {
		t.Fatalf("the host's own identity was not proved when none was asked for: %+v", out)
	}
	other := "EAnotherIdentifierOfTheRightShape0123456789"
	out := askWhoIsAt(t, asker, srv.URL, other)
	if out.Verified || out.Kind != KindDifferent {
		t.Fatalf("a host proving %s was accepted as %s: %+v", proofAgentAID, other, out)
	}
}
