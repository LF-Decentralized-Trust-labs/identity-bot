package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"identity-agent-core/witness"
)

// An internal stand-in, and a name that is not written as a local address but
// resolves to it when dialled. A call that is not guarded reaches the stand-in;
// the stand-in is the proof, not the error text.
func internalStandIn(t *testing.T) (name string, hits *atomic.Int32) {
	t.Helper()
	hits = new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	name = "http://foo.localhost:" + port
	resp, err := http.DefaultClient.Get(name)
	if err != nil {
		t.Skipf("this machine does not resolve foo.localhost: %v", err)
	}
	resp.Body.Close()
	hits.Store(0)
	t.Cleanup(witness.UseDialResolverForTest(func(string) ([]string, error) { return []string{"127.0.0.1"}, nil }))
	return name, hits
}

// A site, an Ask or an invite chooses the address, and the owner only scans it:
// none of them may reach an internal service.
func TestAnAddressAStrangerChoosesNeverReachesAnInternalService(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "")
	name, hits := internalStandIn(t)

	s := agentWithDerivedIdentity(t)
	if err := s.initLoginHandler(); err != nil {
		t.Skipf("login engine unavailable: %v", err)
	}
	h := s.loginHandler
	ask, _ := json.Marshal(signerPayload{OrgName: "O", OrgAID: "EORGAID", SiteAID: "EORGAID", InviteToken: "tok"})
	emp, _ := json.Marshal(map[string]string{"invite_token": "tok", "org_aid": "EORGAID", "site_aid": "EORGAID"})

	calls := map[string]func(){
		"the Ask fetch": func() { _, _ = s.buildAskContext(name + "/i/tok") },
		"the signer invite's redeem": func() {
			_, _ = addSignerAsk{}.Execute(s, AskContext{Base: name, Token: "tok", AskBytes: ask, T: 4}, ScanDecision{Approved: true})
		},
		"the employee invite's redeem": func() {
			_, _ = addEmployeeAsk{}.Execute(s, AskContext{Base: name, Token: "tok", AskBytes: emp, T: 3}, ScanDecision{Approved: true})
		},
	}
	// The login engine's calls to a site go through the client the server
	// gives it (the login package's own test shows every call uses it).
	calls["the login engine's client"] = func() {
		resp, err := h.PeerClient(name).Get(name + "/oobi/ESITE")
		if err == nil {
			resp.Body.Close()
		}
	}
	for what, call := range calls {
		hits.Store(0)
		call()
		if n := hits.Load(); n != 0 {
			t.Errorf("%s: the internal service was reached %d times", what, n)
		}
	}
}

// A local site is reached only when the owner has said they are testing
// against one, in their own environment.
func TestALocalSiteIsReachedOnlyWhereTheOwnerSaidSo(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()

	t.Setenv("IA_ALLOW_LOCAL_SITES", "")
	if resp, err := siteClient(2*time.Second, srv.URL).Get(srv.URL); err == nil {
		resp.Body.Close()
	}
	if hits.Load() != 0 {
		t.Fatal("a local site was reached without the owner choosing it")
	}
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	resp, err := siteClient(2*time.Second, srv.URL).Get(srv.URL)
	if err != nil {
		t.Fatalf("a local site the owner chose was not reached: %v", err)
	}
	resp.Body.Close()
}

// A sealed request goes to the address on record for the peer, and that
// address is checked when it is dialled, not only when it was recorded.
func TestASealedRequestToAnAddressThatResolvesInwardIsNotSent(t *testing.T) {
	name, hits := internalStandIn(t)
	caller, callerAID, _, responderAID := twoAgents(t)
	didcommMu.Lock()
	peers := caller.peersInTest()
	p := peers[responderAID]
	p.Endpoint = name + "/didcomm"
	peers[responderAID] = p
	_ = caller.savePeers(peers)
	didcommMu.Unlock()

	_, _ = caller.SealedRequest(context.Background(), callerAID, responderAID, http.MethodPost, "/api/echo", []byte(`{}`), nil)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the internal service was reached %d times", n)
	}
}

// The same for an ordinary message to a peer.
func TestAMessageToAnAddressThatResolvesInwardIsNotSent(t *testing.T) {
	name, hits := internalStandIn(t)
	caller, callerAID, _, responderAID := twoAgents(t)
	didcommMu.Lock()
	peers := caller.peersInTest()
	p := peers[responderAID]
	p.Endpoint = name + "/didcomm"
	peers[responderAID] = p
	_ = caller.savePeers(peers)
	didcommMu.Unlock()

	_, _, err := caller.SendDIDCommMessage(callerAID, responderAID, "https://didcomm.org/basicmessage/2.0/message", json.RawMessage(`{"content":"hi"}`))
	if err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("the message was not refused at dial time: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the internal service was reached %d times", n)
	}
}
