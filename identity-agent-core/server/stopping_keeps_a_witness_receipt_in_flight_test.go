package server

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
	"identity-agent-core/witness"
)

// recordsReceipts remembers whether each receipt write succeeded.
type recordsReceipts struct {
	*store.SQLiteStore
	mu   sync.Mutex
	errs []error
}

func (r *recordsReceipts) SaveWitnessReceipt(rec store.WitnessReceiptRecord) error {
	err := r.SQLiteStore.SaveWitnessReceipt(rec)
	r.mu.Lock()
	r.errs = append(r.errs, err)
	r.mu.Unlock()
	return err
}

// A witness's receipt on its way when the server is stopped is kept: Stop
// holds the data store open until it is written, rather than closing it
// beneath the write ("database is closed").
func TestStopKeepsAWitnessReceiptThatIsStillOnItsWay(t *testing.T) {
	s := agentWithNoIdentity(t)
	s.running = true
	rec := &recordsReceipts{SQLiteStore: s.DataStore.(*store.SQLiteStore)}
	svc := witness.NewService(witness.NewSQLiteStore(rec.DB()), rec, nil, witness.BackendDesktop)
	s.WitnessService = svc

	const said = "EAnchoringEvent0123456789ABCDEFGHIJKLMNOPQRS"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := iacrypto.NonTransferableAIDQB64(pub)
	if err := rec.SaveContact(store.ContactRecord{AID: "EContactw1", OobiURL: "http://w1.test", IsWitness: true}); err != nil {
		t.Fatal(err)
	}
	_ = svc.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EContactw1", WitnessKey: key})

	arrived, release := make(chan struct{}), make(chan struct{})
	svc.PostEvent = func(context.Context, string, []byte) (map[string]interface{}, error) {
		close(arrived)
		<-release
		sig, _ := login.SignString(said, priv.Seed())
		return map[string]interface{}{"witness_aid": key, "cesr_signature": sig}, nil
	}
	raw := []byte(`{"v":"KERI10JSON000000_","t":"ixn","d":"` + said + `","i":"ERecord","s":"1"}`)
	if err := svc.BroadcastToDesignated(context.Background(), "ERecord", raw, []string{"0Bsig"}, []string{key}, 1); err != nil {
		t.Fatal(err)
	}
	<-arrived

	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	time.Sleep(200 * time.Millisecond)
	close(release)
	select {
	case <-stopped:
	case <-time.After(20 * time.Second):
		t.Fatal("Stop did not return")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.errs) != 1 || rec.errs[0] != nil {
		t.Fatalf("the receipt was not kept: writes %v", rec.errs)
	}
}
