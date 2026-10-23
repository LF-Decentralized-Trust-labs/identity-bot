package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
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

// A delegated identity's real inception and its first interaction, signed by
// its own key, are receipted by a real witness that witnesses for it, and the
// witness can then be asked how far it holds the identity's key log.
func TestARealDelegatedInceptionIsWitnessed(t *testing.T) {
	// The witness: a real one, with its own key.
	witness, _ := testService(t)
	wpub, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	wkey := iacrypto.NonTransferableAIDQB64(wpub)
	witness.SignReceipt = func(said string) (string, string, error) {
		sig, err := login.SignString(said, wpriv.Seed())
		return wkey, sig, err
	}

	// The delegated identity, made by the engine that ships.
	e := keriengine.New()
	key := func() (string, []byte) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		return iacrypto.VerkeyQB64(pub), priv.Seed()
	}
	rootPub, _ := key()
	rootNext, _ := key()
	if _, err := e.CreateInceptionNamed(rootPub, rootNext, "org"); err != nil {
		t.Fatal(err)
	}
	recPub, recSeed := key()
	recNext, _ := key()
	d, err := e.CreateDelegatedInceptionKept(recPub, recNext, "", "org", []string{wkey}, 1, func(drivers.KELKeep) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	dip, _ := base64.StdEncoding.DecodeString(d.RawBytesB64)
	ixn, err := e.Interact(d.AID, []interface{}{map[string]interface{}{"d": d.Said}})
	if err != nil {
		t.Fatal(err)
	}
	ixnRaw, _ := base64.StdEncoding.DecodeString(ixn.RawBytesB64)
	// The witness has agreed to witness for it.
	_ = witness.Store.SaveContactMeta(ContactMeta{ContactAID: d.AID, WitnessingFor: true, BackendType: BackendDesktop})

	// The sender: finds the witness by its key and posts to it.
	sender, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	sender = NewService(sender.Store, kc, nil, BackendDesktop)
	mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", OobiURL: "http://w.test", IsWitness: true}
	_ = sender.Store.SaveContactMeta(ContactMeta{ContactAID: "EWitness", WitnessKey: wkey})
	sender.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		var req struct {
			AID   string `json:"aid"`
			Event string `json:"event_b64"`
			Sig   string `json:"cesr_signature"`
		}
		_ = json.Unmarshal(body, &req)
		raw, _ := base64.StdEncoding.DecodeString(req.Event)
		return witness.ReceiveEvent(req.AID, raw, req.Sig)
	}
	sender.FetchKel = func(_ context.Context, _ string) (KelReply, error) {
		return witness.KelProof(d.AID)
	}
	for _, ev := range [][]byte{dip, ixnRaw} {
		sig, _ := login.SignString(string(ev), recSeed)
		if err := sender.BroadcastToDesignated(context.Background(), d.AID, ev, sig, []string{wkey}, 1); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 100; i++ {
			kc.mu.Lock()
			n := len(kc.kept)
			kc.mu.Unlock()
			if n > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		kc.mu.Lock()
		got := len(kc.kept)
		kc.kept = nil
		kc.mu.Unlock()
		if got != 1 {
			t.Fatalf("the witness did not receipt a real event of the delegated identity")
		}
	}
	held := sender.KelHeldBy(context.Background(), d.AID, []string{wkey})
	if tip, ok := held[wkey]; !ok || tip.SN != 1 || tip.SAID != ixn.Said {
		t.Fatalf("the witness says it holds %+v", held)
	}
}

// A key event's sequence number is hexadecimal. A witness receipts a real key
// log past its tenth and sixteenth events, where reading it as decimal would
// have refused it as out of order.
func TestAWitnessFollowsAKeyLogPastItsSixteenthEvent(t *testing.T) {
	witness, _ := testService(t)
	wpub, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	wkey := iacrypto.NonTransferableAIDQB64(wpub)
	witness.SignReceipt = func(said string) (string, string, error) {
		sig, err := login.SignString(said, wpriv.Seed())
		return wkey, sig, err
	}
	e := keriengine.New()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	icp, err := e.CreateInceptionNamed(iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(nextPub), "id")
	if err != nil {
		t.Fatal(err)
	}
	_ = witness.Store.SaveContactMeta(ContactMeta{ContactAID: icp.AID, WitnessingFor: true, BackendType: BackendDesktop})
	receive := func(rawB64 string) {
		raw, _ := base64.StdEncoding.DecodeString(rawB64)
		sig, _ := login.SignString(string(raw), priv.Seed())
		if _, err := witness.ReceiveEvent(icp.AID, raw, sig); err != nil {
			t.Fatalf("the witness refused a real event: %v", err)
		}
	}
	receive(icp.RawBytesB64)
	var last string
	for i := 1; i <= 17; i++ {
		ixn, err := e.Interact("id", []interface{}{map[string]interface{}{"d": fmt.Sprintf("Eseal%d", i)}})
		if err != nil {
			t.Fatal(err)
		}
		receive(ixn.RawBytesB64)
		last = ixn.Said
	}
	held, _ := witness.GetKelReplica(icp.AID)
	if sn, _ := eventSeq(held[len(held)-1]); sn != 17 || held[len(held)-1]["d"] != last {
		t.Fatalf("the witness holds the key log to %d", sn)
	}
}

// A witness takes on a delegated identity only from the approval it holds in
// the delegator's key log, and only once the inception's own signature holds.
func TestAWitnessTakesOnADelegateOnlyFromItsApproval(t *testing.T) {
	witness, _ := testService(t)
	wpub, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	wkey := iacrypto.NonTransferableAIDQB64(wpub)
	witness.SignReceipt = func(said string) (string, string, error) {
		sig, err := login.SignString(said, wpriv.Seed())
		return wkey, sig, err
	}
	e := keriengine.New()
	key := func() (string, []byte) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		return iacrypto.VerkeyQB64(pub), priv.Seed()
	}
	orgPub, orgSeed := key()
	orgNext, _ := key()
	icp, err := e.CreateInceptionNamed(orgPub, orgNext, "org")
	if err != nil {
		t.Fatal(err)
	}
	send := func(aid, rawB64 string, seed []byte) error {
		raw, _ := base64.StdEncoding.DecodeString(rawB64)
		sig, _ := login.SignString(string(raw), seed)
		_, err := witness.ReceiveEvent(aid, raw, sig)
		return err
	}
	_ = witness.Store.SaveContactMeta(ContactMeta{ContactAID: icp.AID, WitnessingFor: true, BackendType: BackendDesktop})
	if err := send(icp.AID, icp.RawBytesB64, orgSeed); err != nil {
		t.Fatal(err)
	}
	recPub, recSeed := key()
	recNext, _ := key()
	var approval drivers.KELKeep
	d, err := e.CreateDelegatedInceptionKept(recPub, recNext, "", "org", []string{wkey}, 1, func(k drivers.KELKeep) error {
		approval = k
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Before the witness holds the approval, the inception is refused.
	if err := send(d.AID, d.RawBytesB64, recSeed); err == nil {
		t.Fatal("a delegate was witnessed before its approval was held")
	}
	if err := send(icp.AID, base64.StdEncoding.EncodeToString(approval.Raw), orgSeed); err != nil {
		t.Fatalf("the approval: %v", err)
	}
	// Signed by another key, the inception is refused and enrols nobody.
	_, otherSeed := key()
	if err := send(d.AID, d.RawBytesB64, otherSeed); err == nil {
		t.Fatal("a badly signed delegated inception was witnessed")
	}
	if meta, _ := witness.Store.GetContactMeta(d.AID); meta != nil && meta.WitnessingFor {
		t.Fatal("a badly signed delegated inception enrolled its identity")
	}
	if err := send(d.AID, d.RawBytesB64, recSeed); err != nil {
		t.Fatalf("an approved delegate was refused: %v", err)
	}
}
