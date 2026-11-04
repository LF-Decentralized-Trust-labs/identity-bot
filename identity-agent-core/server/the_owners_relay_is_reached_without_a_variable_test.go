package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func countingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// The relay the owner configured is the owner's choice: with only
// IA_DEV_RELAY_URL set (no IA_ALLOW_LOCAL_SITES), the login engine reaches it,
// and a different local address, which a site could name, is still refused.
func TestTheOwnersDevRelayIsReachedWithOnlyItsUrlSet(t *testing.T) {
	relay, relayHits := countingServer(t)
	other, otherHits := countingServer(t)
	t.Setenv("IA_ALLOW_LOCAL_SITES", "")
	t.Setenv("IA_RELAY_URL", "")
	t.Setenv("IA_DEV_RELAY_URL", relay.URL)

	s := agentWithDerivedIdentity(t)
	if err := s.initLoginHandler(); err != nil {
		t.Skipf("login engine unavailable: %v", err)
	}
	h := s.loginHandler
	if h.DevRelay != relay.URL {
		t.Fatalf("the login engine's relay is %q, want %q", h.DevRelay, relay.URL)
	}
	resp, err := h.PeerClient(relay.URL+"/_dev/register").Post(relay.URL+"/_dev/register", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("the owner's own relay was refused: %v", err)
	}
	resp.Body.Close()
	if relayHits.Load() != 1 {
		t.Fatalf("the relay was reached %d times, want 1", relayHits.Load())
	}

	if resp, err := h.PeerClient(other.URL).Get(other.URL); err == nil {
		resp.Body.Close()
	}
	if otherHits.Load() != 0 {
		t.Fatal("a local address that is not the owner's relay was reached")
	}
}

// With nothing set at all the development relay is on this machine at 8765, and
// that default is the owner's setting too; no other local port is.
func TestTheDefaultDevRelayIsTheOwnersToo(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "")
	t.Setenv("IA_RELAY_URL", "")
	t.Setenv("IA_DEV_RELAY_URL", "")
	if !ownerAllowsLocal("http://127.0.0.1:8765/_dev/register") {
		t.Error("the default development relay is refused")
	}
	for _, u := range []string{"http://127.0.0.1:8766/x", "https://127.0.0.1:8765/x", "http://localhost:8765/x", "http://10.0.0.1:8765/x"} {
		if ownerAllowsLocal(u) {
			t.Errorf("%s is allowed, and is not the owner's relay", u)
		}
	}
	// A relay the owner set that is a name, not a local address, grants nothing local.
	if isOwnerRelayLocal("http://relay.example.com/x", "http://relay.example.com") {
		t.Error("a named relay opened the guard")
	}
	if !isOwnerRelayLocal("http://10.0.0.5:9000/x", "http://10.0.0.5:9000") {
		t.Error("an owner-set local address was refused")
	}
}

// The schema fetch (the URL can come from a credential) and the two handlers
// that resolve or add a contact by an OOBI (the owner pastes it, someone else
// wrote it) do not reach an internal service.
func TestAnAddressSomeoneElseWroteIsHeldByTheSchemaAndOobiHandlers(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "")
	t.Setenv("IA_RELAY_URL", "")
	t.Setenv("IA_DEV_RELAY_URL", "")
	name, hits := internalStandIn(t)
	s := agentWithDerivedIdentity(t)

	post := func(h http.HandlerFunc, body string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		done := make(chan struct{})
		go func() { defer close(done); h(w, r) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("the handler did not return")
		}
	}
	for what, call := range map[string]func(){
		"the schema fetch":         func() { post(s.handleFetchCredentialSchema, `{"url":"`+name+`/schema"}`) },
		"resolving a contact OOBI": func() { post(s.handleResolveOobiContact, `{"oobi_url":"`+name+`/oobi/EOTHER"}`) },
		"adding a contact by OOBI": func() { post(s.handleAddContact, `{"oobi_url":"`+name+`/oobi/EOTHER","alias":"x"}`) },
	} {
		hits.Store(0)
		call()
		if n := hits.Load(); n != 0 {
			t.Errorf("%s: the internal service was reached %d times", what, n)
		}
	}
}
