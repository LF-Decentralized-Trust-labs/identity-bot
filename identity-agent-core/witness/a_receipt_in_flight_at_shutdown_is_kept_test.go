package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// closableContacts refuses a write once closed, as a closed database does.
type closableContacts struct {
	*keepingContacts
	closedMu sync.Mutex
	closed   bool
	lost     int
}

func (c *closableContacts) SaveWitnessReceipt(r store.WitnessReceiptRecord) error {
	c.closedMu.Lock()
	defer c.closedMu.Unlock()
	if c.closed {
		c.lost++
		return context.Canceled
	}
	return c.keepingContacts.SaveWitnessReceipt(r)
}

func (c *closableContacts) close() {
	c.closedMu.Lock()
	c.closed = true
	c.closedMu.Unlock()
}

// A witness's receipt that arrives while the agent is stopping is kept: Wait
// holds the caller until it is written, so the store is not closed under it,
// and nothing new is started once Stop has been called.
func TestAReceiptInFlightWhenTheAgentStopsIsKept(t *testing.T) {
	base, mc := testService(t)
	cc := &closableContacts{keepingContacts: &keepingContacts{memContacts: mc}}
	s := NewService(base.Store, cc, nil, BackendDesktop)
	const said = "EAnchoringEvent0123456789ABCDEFGHIJKLMNOPQRS"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := iacrypto.NonTransferableAIDQB64(pub)
	mc.contacts["EContactw1"] = store.ContactRecord{AID: "EContactw1", OobiURL: "http://w1.test", IsWitness: true}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EContactw1", WitnessKey: key})

	arrived, release := make(chan struct{}), make(chan struct{})
	s.PostEvent = func(context.Context, string, []byte) (map[string]interface{}, error) {
		close(arrived)
		<-release
		sig, _ := login.SignString(said, priv.Seed())
		return map[string]interface{}{"witness_aid": key, "cesr_signature": sig}, nil
	}
	raw := []byte(`{"v":"KERI10JSON000000_","t":"ixn","d":"` + said + `","i":"ERecord","s":"1"}`)
	if err := s.BroadcastToDesignated(context.Background(), "ERecord", raw, []string{"0Bsig"}, []string{key}, 1); err != nil {
		t.Fatal(err)
	}
	<-arrived

	s.Stop()
	if s.background(func() { t.Error("work started after Stop") }) {
		t.Fatal("background work was accepted after Stop")
	}
	waited := make(chan struct{})
	go func() {
		s.Wait()
		cc.close() // what the server does once Wait returns
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("Wait returned while a receipt was still on its way")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after the receipt arrived")
	}
	if cc.lost != 0 || len(cc.kept) != 1 {
		t.Fatalf("receipt lost: kept %d, refused as closed %d", len(cc.kept), cc.lost)
	}
}
