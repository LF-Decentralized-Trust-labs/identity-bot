package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"identity-agent-core/witness"
)

// internalPeer is a service on this machine that answers as a peer would, and
// counts how often it was asked.
func internalPeer(t *testing.T, aid string) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"aid": aid, "public_key": "DKey", "alias": "peer"})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// A stranger's introduction names an address on this machine: nothing is
// fetched from it and nothing is recorded.
func TestAnIntroductionAtAnInternalAddressIsNotFetched(t *testing.T) {
	s := serverWithIdentity(t, "EUS")
	srv, hits := internalPeer(t, "ESTRANGER")

	body, _ := json.Marshal(map[string]string{"sender_oobi": srv.URL + "/oobi/ESTRANGER"})
	err := (contactRequest{}).Perform(s, InboundMessage{FromAID: "ESTRANGER", Body: body})
	if err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatal("an introduction at an internal address was followed")
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Fatalf("the internal service was called %d times", n)
	}
	if c, _ := s.DataStore.GetContact("ESTRANGER"); c != nil && c.AID != "" {
		t.Fatalf("a contact was recorded: %+v", c)
	}
}

// A name that resolves to a public address when it is checked and to a loopback
// address when it is dialled is refused at the dial.
func TestANameThatChangesWhereItPointsIsNotFetched(t *testing.T) {
	s := serverWithIdentity(t, "EUS")
	srv, hits := internalPeer(t, "ESTRANGER")
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	restore := witness.UseDialResolverForTest(func(string) ([]string, error) { return []string{"127.0.0.1"}, nil })
	defer restore()

	body, _ := json.Marshal(map[string]string{"sender_oobi": "http://peer.example:" + port + "/oobi/ESTRANGER"})
	if err := (contactRequest{}).Perform(s, InboundMessage{FromAID: "ESTRANGER", Body: body}); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatal("a name that resolved to loopback when dialled was fetched")
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Fatalf("the internal service was called %d times", n)
	}
	// The same on the Ask path, which takes the address from the asker.
	if _, _, err := s.EnsureKeriContact("http://peer.example:" + port + "/oobi/ESTRANGER"); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatal("EnsureKeriContact followed a name that resolved to loopback when dialled")
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Fatalf("the internal service was called %d times", n)
	}
}
