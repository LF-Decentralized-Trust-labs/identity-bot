package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// A name that is public when checked and loopback when dialled is refused on
// every GET and POST this package makes to an address a contact supplied.
func TestANameThatChangesWhereItPointsIsRefusedOnEveryPath(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"service_aid":"EAnyone"}`))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	restore := UseDialResolverForTest(func(string) ([]string, error) { return []string{"127.0.0.1"}, nil })
	defer restore()
	base := "http://peer.example:" + port
	ctx := context.Background()

	s, mc := testService(t)
	paths := map[string]func() error{
		"tip": func() error { _, err := s.defaultFetchTip(ctx, base+"/witness/tip"); return err },
		"event": func() error {
			_, err := s.defaultFetchEvent(ctx, base+"/witness/kel/E/event/0")
			return err
		},
		"post": func() error { _, err := s.defaultPostEvent(ctx, base+"/witness/event", []byte(`{}`)); return err },
		"identity": func() error {
			_, err := LiveIdentityOf(ctx, base)
			return err
		},
	}
	for name, call := range paths {
		// The refusal must be the dial check, not a name that failed to resolve.
		if err := call(); err == nil || !strings.Contains(err.Error(), "internal address") {
			t.Errorf("%s: a name that resolved to loopback when dialled was not refused at the dial: %v", name, err)
		}
	}

	// The heartbeat records a failure rather than an error.
	mc.contacts["EW"] = store.ContactRecord{AID: "EW", OobiURL: base + "/public/oobi/EW", IsWitness: true}
	s.runHeartbeatPass(ctx)
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the internal service was called %d times", n)
	}
}

// A contact a stranger's message created, whose key is the one a peer witness
// is named by, is not that witness: events are posted to no one but the owner's
// contact.
func TestAStrangerClaimingAWitnessKeyGetsNoEvents(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := iacrypto.NonTransferableAIDQB64(pub)

	for name, c := range map[string]store.ContactRecord{
		"a pending request":             {AID: "EStranger", OobiURL: "http://stranger.test", Status: "pending_inbound", ContactSource: ContactSourceInbound},
		"an introduction, not accepted": {AID: "EStranger", OobiURL: "http://stranger.test", Status: "unchecked", ContactSource: "keri"},
	} {
		t.Run(name, func(t *testing.T) {
			mc.contacts["EStranger"] = c
			_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EStranger", WitnessKey: key})
			if _, ok := s.designatedTargets([]string{key})[key]; ok {
				t.Fatal("a stranger's contact was mapped to the witness key")
			}
			var posted int32
			s.PostEvent = func(context.Context, string, []byte) (map[string]interface{}, error) {
				atomic.AddInt32(&posted, 1)
				return nil, nil
			}
			raw := []byte(`{"v":"KERI10JSON000000_","t":"ixn","d":"ESAID","i":"ERecord","s":"1"}`)
			_ = s.BroadcastToDesignated(context.Background(), "ERecord", raw, "0Bsig", []string{key}, 1)
			s.BringUpToDate(context.Background(), "ERecord", []SignedEvent{{RawBytesB64: "AAAA", CesrSignature: "0B"}}, []string{key}, 1)
			if n := atomic.LoadInt32(&posted); n != 0 {
				t.Fatalf("%d events were posted to a stranger", n)
			}
		})
	}

	// The owner accepting the same contact makes it reachable.
	mc.contacts["EStranger"] = store.ContactRecord{AID: "EStranger", OobiURL: "http://stranger.test", Status: "accepted", ContactSource: "keri"}
	if _, ok := s.designatedTargets([]string{key})[key]; !ok {
		t.Fatal("an accepted contact is not mapped to its witness key")
	}
}
