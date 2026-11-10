package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// onReceipt does not count a witness it already holds, so a broadcast that
// restarted the count at 0 would leave an event that is sent again with one
// receipt too few for good: the first witness is skipped, the second makes it 1.
// The count is the receipts kept, whatever restarts it.
func TestAnEventBroadcastAgainKeepsTheReceiptsItHas(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	const said = "EAgainEvent0123456789ABCDEFGHIJKLMNOPQRSTUVW"
	var keys [2]string
	var privs [2]ed25519.PrivateKey
	for i := range keys {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[i], privs[i] = iacrypto.NonTransferableAIDQB64(pub), priv
		aid := "EContactw" + string(rune('1'+i))
		mc.contacts[aid] = store.ContactRecord{AID: aid, OobiURL: "http://w" + string(rune('1'+i)) + ".test", IsWitness: true}
		_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: aid, WitnessKey: keys[i]})
	}
	secondUp := false
	s.PostEvent = func(_ context.Context, url string, _ []byte) (map[string]interface{}, error) {
		i := 0
		if url != witnessEventURL(witnessTarget{URL: "http://w1.test"}) {
			i = 1
			if !secondUp {
				return nil, errors.New("down")
			}
		}
		sig, _ := login.SignString(said, privs[i].Seed())
		return map[string]interface{}{"witness_aid": keys[i], "cesr_signature": sig}, nil
	}
	raw := []byte(`{"v":"KERI10JSON000000_","t":"ixn","d":"` + said + `","i":"ERecord","s":"1"}`)
	send := func() {
		t.Helper()
		if err := s.BroadcastToDesignated(context.Background(), "ERecord", raw, []string{"0Bsig"}, keys[:], 2); err != nil {
			t.Fatal(err)
		}
	}
	// The sends are in the background and the finalization's own timer outlives them, so the count is waited for.
	settled := func(count int, state string) *FinalizationState {
		t.Helper()
		var f *FinalizationState
		for i := 0; i < 200; i++ {
			if f, _ = s.Store.GetFinalization(said); f != nil && f.ReceiptCount == count && f.State == state {
				return f
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("expected %d receipts, %s; it is %+v", count, state, f)
		return nil
	}
	defer s.Stop()
	send()
	settled(1, FinalizePartial)
	secondUp = true
	send()
	// Two distinct witnesses receipted it, across two broadcasts. Before the count was taken from the
	// receipts kept it restarted at 0, the first witness was skipped as already held, and it stayed at 1.
	settled(2, FinalizeFinalized)
	// Sent a third time, with both receipts held, it stays finalized at 2.
	send()
	time.Sleep(200 * time.Millisecond)
	settled(2, FinalizeFinalized)
}
