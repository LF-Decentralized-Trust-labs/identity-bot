package witness

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"identity-agent-core/store"
)

// loopbackWhenDialled makes a name look public when checked and resolve to
// 127.0.0.1 when dialled, and returns the port of a server that counts hits.
func loopbackWhenDialled(t *testing.T) (port string, hits *atomic.Int32) {
	t.Helper()
	hits = new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"status":"accepted"}`))
	}))
	t.Cleanup(srv.Close)
	_, port, _ = net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	oldLookup, oldDial := lookupHost, dialResolve
	lookupHost = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
	dialResolve = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	t.Cleanup(func() { lookupHost, dialResolve = oldLookup, oldDial })
	return port, hits
}

// An answer to a name that was public when checked and is 127.0.0.1 when
// dialled never reaches the local server: SendAcceptCallback to
// defaultPostEvent, with nothing replaced in between.
func TestAnAnswerToANameThatTurnsInwardWhenDialledIsNotSent(t *testing.T) {
	const aid = "ERequester0000000000000000000000000000000000031"
	port, hits := loopbackWhenDialled(t)
	s, _, _ := answerer(t, map[string]store.ContactRecord{aid: {AID: aid, OobiURL: "http://rebind.example:" + port + "/public/oobi/" + aid}})
	s.PostEvent = s.defaultPostEvent
	if err := s.SendAcceptCallback(context.Background(), "", declined(aid)); err == nil {
		t.Fatal("the answer was sent")
	}
	if hits.Load() != 0 {
		t.Fatal("the local server was reached")
	}
}

// The owner's local agent, written as a local address, is still answered
// through the same path: the answer's own decision about local is what lets it.
func TestAnAnswerToTheOwnersLocalAgentIsSentThroughTheRealPost(t *testing.T) {
	const aid = "ERequester0000000000000000000000000000000000032"
	_, hits := loopbackWhenDialled(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write([]byte(`{}`)) }))
	defer srv.Close()
	s, _, _ := answerer(t, map[string]store.ContactRecord{aid: {AID: aid, OobiURL: srv.URL + "/public/oobi/" + aid}})
	s.PostEvent = s.defaultPostEvent
	if err := s.SendAcceptCallback(context.Background(), "", declined(aid)); err != nil {
		t.Fatalf("the owner's local agent was not answered: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
}

// A witness request, an event broadcast, a withdrawal and a submission are
// held to the address they dial, whatever the name resolved to when checked,
// and none goes through a proxy.
func TestTheOtherWitnessPostsAreHeldToTheAddressDialled(t *testing.T) {
	const aid = "EWitness0000000000000000000000000000000000033"
	port, hits := loopbackWhenDialled(t)
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)

	name := "http://rebind.example:" + port
	s, _, _ := answerer(t, map[string]store.ContactRecord{aid: {AID: aid, OobiURL: name + "/public/oobi/" + aid, ContactSource: "keri"}})
	s.PostEvent = s.defaultPostEvent
	c, _ := s.Contacts.GetContact(aid)

	if _, err := s.postWitnessRequest(context.Background(), c, "r1", false); err == nil {
		t.Error("postWitnessRequest reached a name that turned inward")
	}
	if _, err := s.SubmitToWitness(context.Background(), name+"/api/witness/events", "EA", []byte(`{"d":"ESAID"}`), "sig"); err == nil {
		t.Error("an event submission reached a name that turned inward")
	}
	if _, err := s.PostEvent(s.ownersLocalAllowed(context.Background(), name+"/x"), name+"/x", []byte(`{}`)); err == nil {
		t.Error("a broadcast reached a name that turned inward")
	}
	if hits.Load() != 0 || proxied.Load() != 0 {
		t.Fatalf("local server hit %d times, proxy %d", hits.Load(), proxied.Load())
	}
}

func TestMoreAddressesAreInternal(t *testing.T) {
	for ip, want := range map[string]bool{
		"0.0.0.0": true, "0.1.2.3": true, "198.18.0.1": true, "198.19.255.255": true, "198.20.0.1": false, "198.17.255.255": false,
		"240.0.0.1": true, "255.255.255.255": true, "239.1.1.1": true, "224.0.0.251": true, "ff02::1": true, "ff0e::1": true,
		"64:ff9b::7f00:1": true, "64:ff9b::a00:5": true, "64:ff9b::c0a8:1": true, "64:ff9b::a9fe:a9fe": true, "64:ff9b::5db8:d822": false,
		"2001:db8::1": false, "93.184.216.34": false,
	} {
		if got := ipIsInternal(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v, want %v", ip, got, want)
		}
	}
}
