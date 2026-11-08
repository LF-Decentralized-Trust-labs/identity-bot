package witness

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// A post waiting to retry ends when the service stops: Wait returns at once
// rather than after the retry delay, and the second attempt is never made.
func TestAPostThatIsRetryingDoesNotHoldUpStop(t *testing.T) {
	s, mc := testService(t)
	const said = "EAnchoringEvent0123456789ABCDEFGHIJKLMNOPQRS"
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := iacrypto.NonTransferableAIDQB64(pub)
	mc.contacts["EContactw1"] = store.ContactRecord{AID: "EContactw1", OobiURL: "http://w1.test", IsWitness: true}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EContactw1", WitnessKey: key})

	var attempts int32
	failed := make(chan struct{}, 1)
	s.PostEvent = func(context.Context, string, []byte) (map[string]interface{}, error) {
		atomic.AddInt32(&attempts, 1)
		select {
		case failed <- struct{}{}:
		default:
		}
		return nil, errors.New("witness unreachable")
	}
	raw := []byte(`{"v":"KERI10JSON000000_","t":"ixn","d":"` + said + `","i":"ERecord","s":"1"}`)
	if err := s.BroadcastToDesignated(context.Background(), "ERecord", raw, []string{"0Bsig"}, []string{key}, 1); err != nil {
		t.Fatal(err)
	}
	<-failed // the first attempt failed, so the post is now waiting to retry

	start := time.Now()
	s.Stop()
	done := make(chan struct{})
	go func() { s.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("Wait was held for the retry delay (%s)", BroadcastRetryDelay)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("stopping took %s", took)
	}
	if n := atomic.LoadInt32(&attempts); n != 1 {
		t.Fatalf("a retry was made after Stop: %d attempts", n)
	}
}
