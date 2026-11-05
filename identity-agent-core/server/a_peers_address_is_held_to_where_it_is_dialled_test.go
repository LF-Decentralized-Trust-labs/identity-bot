package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// Every call this agent makes to an address a peer or a contact supplied is held
// to the address actually dialled: a name that points at an internal service
// when called is never reached, and the internal stand-in is the proof, not the
// error text. A local address is reached only where the owner recorded that
// contact.
func TestACallToAPeersAddressNeverReachesAnInternalService(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	// Not written as a local address, yet resolves to loopback by itself, so
	// a call that is not guarded reaches the server (the control).
	name := "http://foo.localhost:" + port
	if resp, err := http.DefaultClient.Get(name); err != nil {
		t.Skipf("this machine does not resolve foo.localhost: %v", err)
	} else {
		resp.Body.Close()
	}
	hits.Store(0)
	defer witness.UseDialResolverForTest(func(string) ([]string, error) { return []string{"127.0.0.1"}, nil })()

	dir := t.TempDir()
	s := &CoreServer{DataDir: dir, DataStore: testDataStore(t, dir), KeriDriver: nil}
	calls := map[string]func(){
		"the Ask's signer":    func() { _, _ = s.resolveSignerKey(name + "/oobi/EAID") },
		"a contact's key log": func() { _, _ = s.fetchKELFromOOBI(name + "/public/oobi/EAID") },
		"a witness's address": func() { _, _ = s.askWitnessForEndpoint(name, "EAID", nil) },
		"a peer's keys":       func() { _ = s.rememberPeerAt("EAID", name) },
		"a peer's endpoint": func() {
			resp, err := s.peerClient(2*time.Second, name+"/didcomm").Post(name+"/didcomm", "application/json", nil)
			if err == nil {
				resp.Body.Close()
			}
		},
	}
	for what, call := range calls {
		call()
		if n := hits.Load(); n != 0 {
			t.Errorf("%s: the internal service was reached %d times", what, n)
			hits.Store(0)
		}
	}
}

// A local address is dialled for a contact the owner recorded and for no one
// else.
func TestALocalPeerIsReachedOnlyWhereTheOwnerRecordedIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer srv.Close()
	dir := t.TempDir()
	ds := testDataStore(t, dir)
	s := &CoreServer{DataDir: dir, DataStore: ds}

	reach := func() bool {
		resp, err := s.peerClient(2*time.Second, srv.URL).Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err == nil
	}
	if reach() {
		t.Fatal("a local address nobody recorded was reached")
	}
	for source, want := range map[string]bool{witness.ContactSourceInbound: false, "keri": true} {
		if err := ds.SaveContact(store.ContactRecord{AID: "EPeer", OobiURL: srv.URL + "/public/oobi/EPeer", ContactSource: source}); err != nil {
			t.Fatal(err)
		}
		if got := reach(); got != want {
			t.Errorf("contact source %q: reached = %v, want %v", source, got, want)
		}
	}
}

// ownerRecordsContactAt stands in for the owner having added the contact at a
// local test address, which is the one case a local address is dialled.
func ownerRecordsContactAt(t *testing.T, s *CoreServer, aid, base string) {
	t.Helper()
	if s.DataStore == nil {
		s.DataStore = testDataStore(t, t.TempDir())
	}
	if err := s.DataStore.SaveContact(store.ContactRecord{AID: aid, OobiURL: base + "/public/oobi/" + aid, ContactSource: "keri"}); err != nil {
		t.Fatal(err)
	}
}
