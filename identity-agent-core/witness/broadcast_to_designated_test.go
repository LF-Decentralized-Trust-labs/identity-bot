package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

type keepingContacts struct {
	*memContacts
	mu   sync.Mutex
	kept []store.WitnessReceiptRecord
}

func (k *keepingContacts) SaveWitnessReceipt(r store.WitnessReceiptRecord) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.kept = append(k.kept, r)
	return nil
}

// An event goes to exactly the witnesses its identity names, found by their
// keys, and each one's verified receipt is kept.
func TestAnEventGoesToTheWitnessesItsIdentityNames(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	const said = "EAnchoringEvent0123456789ABCDEFGHIJKLMNOPQRS"
	seeds := map[string][]byte{}
	var named []string
	for i, host := range []string{"w1", "w2", "w3"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		key := iacrypto.NonTransferableAIDQB64(pub)
		aid := "EContact" + host
		mc.contacts[aid] = store.ContactRecord{AID: aid, OobiURL: "http://" + host + ".test", IsWitness: true}
		_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: aid, WitnessKey: key})
		seeds[host] = priv.Seed()
		if i < 2 {
			named = append(named, key)
		}
	}
	var mu sync.Mutex
	asked := map[string]bool{}
	s.PostEvent = func(_ context.Context, url string, _ []byte) (map[string]interface{}, error) {
		host := strings.TrimSuffix(strings.TrimPrefix(url, "http://"), ".test/witness/event")
		host = strings.SplitN(host, ".", 2)[0]
		mu.Lock()
		asked[host] = true
		mu.Unlock()
		seed := seeds[host]
		sig, _ := login.SignString(said, seed)
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		return map[string]interface{}{"witness_aid": iacrypto.NonTransferableAIDQB64(pub), "cesr_signature": sig}, nil
	}
	raw := []byte(`{"v":"KERI10JSON000000_","t":"ixn","d":"` + said + `","i":"ERecord","s":"1"}`)
	if err := s.BroadcastToDesignated(context.Background(), "ERecord", raw, "0Bsig", named, 2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		kc.mu.Lock()
		n := len(kc.kept)
		kc.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	kc.mu.Lock()
	defer kc.mu.Unlock()
	if len(kc.kept) != 2 {
		t.Fatalf("kept %d receipts, want the two named witnesses'", len(kc.kept))
	}
	mu.Lock()
	defer mu.Unlock()
	if asked["w3"] {
		t.Fatal("a witness the identity does not name was sent the event")
	}
}
