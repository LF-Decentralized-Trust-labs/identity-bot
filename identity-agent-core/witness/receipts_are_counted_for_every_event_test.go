package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// A witness a rotation cut is still sent the events from before the cut, and
// is not sent anything after it. Those earlier events are counted against the
// set the log gave them, so without its receipt they could never finalise.
func TestAWitnessCutByARotationIsStillSentTheEventsBeforeIt(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)

	seeds := map[string][]byte{}
	keyOf := map[string]string{}
	for _, host := range []string{"w1", "w2", "w3"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		key := iacrypto.NonTransferableAIDQB64(pub)
		aid := "EContact" + host
		mc.contacts[aid] = store.ContactRecord{AID: aid, OobiURL: "http://" + host + ".test", IsWitness: true}
		_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: aid, WitnessKey: key})
		seeds[host], keyOf[host] = priv.Seed(), key
	}
	hostOf := func(url string) string {
		return strings.SplitN(strings.TrimPrefix(url, "http://"), ".", 2)[0]
	}

	k0, _ := keri.GenerateSigner(true)
	k1, _ := keri.GenerateSigner(true)
	k2, _ := keri.GenerateSigner(true)
	pub0, _ := k0.PublicKey()
	pub1, _ := k1.PublicKey()
	pub2, _ := k2.PublicKey()
	d1, _ := keri.NextDigest(pub1)
	d2, _ := keri.NextDigest(pub2)
	two := 2
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub0}, NextDigests: []string{d1},
		Witnesses: []string{keyOf["w1"], keyOf["w2"]}, Toad: &two,
	})
	if err != nil {
		t.Fatal(err)
	}
	icpEv, _ := keri.ParseEvent(icp)
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: icpEv.Identifier, Keys: []string{pub1}, PriorSAID: icpEv.SAID, SN: 1, NextDigests: []string{d2},
		PriorWitnesses: []string{keyOf["w1"], keyOf["w2"]},
		Cuts:           []string{keyOf["w1"]}, Adds: []string{keyOf["w3"]}, Toad: &two,
	})
	if err != nil {
		t.Fatal(err)
	}
	events := []SignedEvent{
		{RawBytesB64: base64.StdEncoding.EncodeToString(icp), CesrSignature: "0Bsig"},
		{RawBytesB64: base64.StdEncoding.EncodeToString(rot), CesrSignature: "0Bsig"},
	}

	s.FetchTip = func(_ context.Context, url string) (TipAnswer, error) {
		host := hostOf(strings.SplitN(url, "/witness/", 2)[0])
		_, nonce, _ := strings.Cut(url, "?nonce=")
		sig, _ := login.SignString(TipStatement(icpEv.Identifier, nonce, -1, ""), seeds[host])
		return TipAnswer{AID: icpEv.Identifier, Nonce: nonce, SN: -1, WitnessAID: keyOf[host], Signature: sig}, nil
	}
	var mu sync.Mutex
	sent := map[string][]int{}
	s.PostEvent = func(_ context.Context, url string, body []byte) (map[string]interface{}, error) {
		host := hostOf(url)
		var req struct {
			Event string `json:"event_b64"`
		}
		_ = json.Unmarshal(body, &req)
		raw, _ := base64.StdEncoding.DecodeString(req.Event)
		ev, _ := keri.ParseEvent(raw)
		mu.Lock()
		sent[host] = append(sent[host], int(ev.SN))
		mu.Unlock()
		sig, _ := login.SignString(ev.SAID, seeds[host])
		return map[string]interface{}{"witness_aid": keyOf[host], "cesr_signature": sig}, nil
	}

	s.BringUpToDate(context.Background(), icpEv.Identifier, events, []string{keyOf["w2"], keyOf["w3"]})

	mu.Lock()
	defer mu.Unlock()
	if got := sent["w1"]; len(got) != 1 || got[0] != 0 {
		t.Fatalf("the witness the rotation cut was sent events %v, want only the one before the cut", got)
	}
	if got := sent["w2"]; len(got) != 2 {
		t.Fatalf("a witness still designated was sent %v", got)
	}
	if f, _ := s.Store.GetFinalization(icpEv.SAID); f == nil || f.State != FinalizeFinalized || f.ReceiptCount != 2 {
		t.Fatalf("the inception, which needs the cut witness's receipt, is %+v", f)
	}
}

func finalizedEvent(t *testing.T, s *Service, kc *keepingContacts, said string) {
	t.Helper()
	now := NowRFC3339()
	if err := s.Store.SaveFinalization(FinalizationState{
		EventSAID: said, SignerAID: "ERecord", State: FinalizeFinalized, Threshold: 2, ReceiptCount: 2,
		StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

// Sending an event again does not lower its count or undo its finalisation.
func TestARebroadcastDoesNotUndoAFinalisedEvent(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	const said = "EAnchoringEvent0123456789ABCDEFGHIJKLMNOPQRS"
	finalizedEvent(t, s, kc, said)
	s.PostEvent = func(context.Context, string, []byte) (map[string]interface{}, error) {
		return nil, context.Canceled
	}
	raw := []byte(`{"v":"KERI10JSON000000_","t":"ixn","d":"` + said + `","i":"ERecord","s":"1"}`)
	if err := s.BroadcastToDesignated(context.Background(), "ERecord", raw, "0Bsig", nil, 2); err != nil {
		t.Fatal(err)
	}
	f, _ := s.Store.GetFinalization(said)
	if f == nil || f.State != FinalizeFinalized || f.ReceiptCount != 2 {
		t.Fatalf("a rebroadcast left the event %+v", f)
	}
	if _, timedOut := s.timeOut(said, 2); timedOut {
		t.Fatal("an event that reached its threshold was timed out")
	}
}

// The timeout is reported with the lock released, so a listener that does not
// return cannot stall the counting of receipts.
func TestATimeoutIsReportedWithoutHoldingTheCountingLock(t *testing.T) {
	base, mc := testService(t)
	s := NewService(base.Store, &keepingContacts{memContacts: mc}, nil, BackendDesktop)
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{
		EventSAID: "ESlow", SignerAID: "ERecord", State: FinalizePending, Threshold: 2, StartedAt: now, UpdatedAt: now,
	})
	count, timedOut := s.timeOut("ESlow", 2)
	if !timedOut || count != 0 {
		t.Fatalf("timeOut = %d, %v", count, timedOut)
	}
	if !s.finalizationMu.TryLock() {
		t.Fatal("the counting lock is still held after the timeout was decided")
	}
	s.finalizationMu.Unlock()
	if f, _ := s.Store.GetFinalization("ESlow"); f.State != FinalizeTimeout {
		t.Fatalf("state %s", f.State)
	}
}
