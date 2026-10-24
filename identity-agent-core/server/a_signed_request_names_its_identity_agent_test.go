package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/store"
)

// namedAgent is an Identity Agent with an identifier and one authorised
// machine. Two built with the same test name hold a grant for the same machine
// key, which is the case a replay across Identity Agents needs.
func namedAgent(t *testing.T, aid string) (*CoreServer, string, []byte) {
	t.Helper()
	s := newAuthTestServer(t)
	ds, err := store.NewSQLiteStore(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	s.DataStore = ds
	if err := ds.SaveIdentity(store.IdentityState{AID: aid}); err != nil {
		t.Fatal(err)
	}
	machine, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	return s, machine, seed
}

const (
	agentA = "EIdentityAgentA0123456789ABCDEFGHIJKLMNOPQR"
	agentB = "EIdentityAgentB0123456789ABCDEFGHIJKLMNOPQR"
)

// A request a machine signed for one Identity Agent is refused by another that
// holds a grant for the same machine, inside the window and before either has
// seen it.
func TestAControllerRequestForOneIdentityAgentIsRefusedByAnother(t *testing.T) {
	a, machine, seed := namedAgent(t, agentA)
	b, machineAtB, _ := namedAgent(t, agentB)
	if machine != machineAtB {
		t.Fatal("the two Identity Agents do not hold a grant for the same machine, so this proves nothing")
	}

	captured := asThatMachineTo(t, agentA, machine, "GET", "/api/profile", "", seed, "", time.Time{})
	copyForB := remote("GET", "/api/profile", "")
	copyForB.Header = captured.Header.Clone()

	w := httptest.NewRecorder()
	b.buildRouter("").ServeHTTP(w, copyForB)
	if w.Code != http.StatusForbidden {
		t.Fatalf("Identity Agent B admitted a request signed for A: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	a.buildRouter("").ServeHTTP(w, captured)
	if w.Code == http.StatusForbidden {
		t.Fatalf("the Identity Agent it was signed for refused it: %s", w.Body.String())
	}
}

// Renaming the target in the header does not help: the name is inside the
// signature.
func TestTheIdentityAgentNamedCannotBeChangedInFlight(t *testing.T) {
	b, machine, seed := namedAgent(t, agentB)
	req := asThatMachineTo(t, agentA, machine, "GET", "/api/profile", "", seed, "", time.Time{})
	req.Header.Set(headerControllerFor, agentB)
	w := httptest.NewRecorder()
	b.buildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a request re-addressed in flight was admitted: %d %s", w.Code, w.Body.String())
	}
}

// A named Identity Agent refuses a request that names nobody, except the one a
// machine makes to learn which identity it acts for.
func TestARequestNamingNobodyIsOnlyForLearningTheName(t *testing.T) {
	s, machine, seed := namedAgent(t, agentA)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, machine, "GET", "/api/profile", "", seed, "", time.Time{}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a request naming no Identity Agent was admitted at a named one: %d", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, machine, "GET", controllerLearnsWhoItActsFor, "", seed, "", time.Time{}))
	if w.Code != http.StatusOK {
		t.Fatalf("a machine could not learn which identity it acts for: %d %s", w.Code, w.Body.String())
	}
}

// A body's request for one Identity Agent is refused by any other: the check
// runs before the signature, so it holds whatever that other has enrolled.
func TestABodyRequestNamesItsIdentityAgent(t *testing.T) {
	m := newTestMachine(t)
	a := &CoreServer{DataDir: t.TempDir()}
	ds, err := store.NewSQLiteStore(a.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	a.DataStore = ds
	if err := ds.SaveIdentity(store.IdentityState{AID: agentA}); err != nil {
		t.Fatal(err)
	}
	req := m.signed(t, a, "POST", "/api/mcp", []byte("{}"))
	if got := req.Header.Get("X-IA-Body-For"); got != agentA {
		t.Fatalf("the request named %q, not the Identity Agent it was signed for", got)
	}
	if err := verifyBodySignature(req, bindingFor(t, m), agentB); err == nil {
		t.Fatal("Identity Agent B took a body request signed for A")
	}
	req = m.signed(t, a, "POST", "/api/mcp", []byte("{}"))
	req.Header.Set("X-IA-Body-For", agentB)
	if err := verifyBodySignature(req, bindingFor(t, m), agentB); err == nil {
		t.Fatal("a body request re-addressed in flight was taken")
	}
	req = m.signed(t, a, "POST", "/api/mcp", []byte("{}"))
	if err := verifyBodySignature(req, bindingFor(t, m), agentA); err != nil {
		t.Fatalf("the Identity Agent the request was signed for refused it: %v", err)
	}
}

// bindingFor is just enough of a body's binding to check its signature.
func bindingFor(t *testing.T, m testMachine) agentbody.Binding {
	t.Helper()
	host, verkey, err := agentbody.Identity(m)
	if err != nil {
		t.Fatal(err)
	}
	return agentbody.Binding{Keys: agentbody.Keys{Host: host, Verkey: verkey}}
}
