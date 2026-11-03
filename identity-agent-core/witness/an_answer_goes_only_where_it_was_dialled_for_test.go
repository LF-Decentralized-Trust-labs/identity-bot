package witness

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"identity-agent-core/store"
)

// A POST with a body is not sent on to wherever the receiver redirects it.
func TestAnAnswerIsNotRedirected(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	for _, code := range []int{301, 302, 307, 308} {
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL, code)
		}))
		s, _, _ := answerer(t, map[string]store.ContactRecord{})
		s.PostEvent = s.defaultPostEvent
		// local: the test server is on loopback.
		for _, ctx := range []context.Context{context.WithValue(context.Background(), guardKey{}, true), context.Background()} {
			_, _ = s.PostEvent(ctx, first.URL, []byte(`{"secret":1}`))
		}
		first.Close()
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("a redirect was followed %d times", n)
	}
}

// What is dialled is checked, so a name that resolved to a public address when
// checked and to an internal one when called is not called.
func TestTheAddressDialledIsCheckedNotOnlyTheName(t *testing.T) {
	var hit atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Add(1) }))
	defer srv.Close()
	if resp, err := guardedClient(5*time.Second, false).Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("an internal address was dialled for a name that is not local")
	}
	if hit.Load() != 0 {
		t.Fatal("the internal server was reached")
	}
	resp, err := guardedClient(5*time.Second, true).Get(srv.URL)
	if err != nil {
		t.Fatalf("a local contact recorded by the owner was refused: %v", err)
	}
	resp.Body.Close()
}

func TestSharedAddressSpaceIsInternal(t *testing.T) {
	for ip, want := range map[string]bool{"100.64.0.1": true, "100.127.255.255": true, "100.63.255.255": false, "100.128.0.1": false, "93.184.216.34": false, "::ffff:100.64.0.1": true} {
		if got := ipIsInternal(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v, want %v", ip, got, want)
		}
	}
}

// The AID is checked whatever the shape of the recorded address, and a local
// address a stranger's request recorded is not a local agent.
func TestTheRecordedAddressMustNameTheRequesterAndBeTheOwners(t *testing.T) {
	const aid = "ERequester0000000000000000000000000000000000024"
	lookupHost = func(h string) ([]net.IP, error) {
		if ip := net.ParseIP(h); ip != nil {
			return []net.IP{ip}, nil
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	t.Cleanup(func() { lookupHost = net.LookupIP })
	cases := map[string]struct {
		c  store.ContactRecord
		ok bool
	}{
		"no oobi path, no AID":       {store.ContactRecord{AID: aid, OobiURL: "https://peer.example/"}, false},
		"no oobi path, other path":   {store.ContactRecord{AID: aid, OobiURL: "https://peer.example/agent"}, false},
		"did:webs layout":            {store.ContactRecord{AID: aid, OobiURL: "https://peer.example/" + aid + "/oobi"}, true},
		"somebody else's AID":        {store.ContactRecord{AID: aid, OobiURL: "https://peer.example/EVictim/oobi"}, false},
		"owner's local agent":        {store.ContactRecord{AID: aid, OobiURL: "http://127.0.0.1:5050/oobi/" + aid}, true},
		"a stranger's local address": {store.ContactRecord{AID: aid, OobiURL: "http://127.0.0.1:5050/oobi/" + aid, ContactSource: ContactSourceInbound}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, _, cap := answerer(t, map[string]store.ContactRecord{aid: c.c})
			err := s.SendAcceptCallback(context.Background(), "", declined(aid))
			if (err == nil) != c.ok || (len(cap.posts) == 1) != c.ok {
				t.Fatalf("err %v, posts %+v", err, cap.posts)
			}
		})
	}
}
