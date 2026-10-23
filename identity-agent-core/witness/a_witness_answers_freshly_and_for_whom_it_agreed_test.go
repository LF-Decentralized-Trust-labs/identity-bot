package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// delegation is an organisation a real witness witnesses for, and an identity
// it delegated, approved in its key log.
type delegation struct {
	w                     *Service
	mc                    *memContacts
	wkey                  string
	e                     *keriengine.Engine
	org, delegate         string
	orgSeed, delegateSeed []byte
	icpB64, approvalB64   string
	dipB64                string
}

func newDelegation(t *testing.T) *delegation {
	t.Helper()
	w, mc := testService(t)
	wpub, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	wkey := iacrypto.NonTransferableAIDQB64(wpub)
	w.SignReceipt = func(msg string) (string, string, error) {
		sig, err := login.SignString(msg, wpriv.Seed())
		return wkey, sig, err
	}
	w.OurWitnessAID = func() (string, error) { return wkey, nil }
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
	agreeToWitness(t, w, mc, icp.AID, true)
	return &delegation{w: w, mc: mc, wkey: wkey, e: e, org: icp.AID, delegate: d.AID, orgSeed: orgSeed, delegateSeed: recSeed,
		icpB64: icp.RawBytesB64, approvalB64: base64.StdEncoding.EncodeToString(approval.Raw), dipB64: d.RawBytesB64}
}

func (d *delegation) send(aid, rawB64 string, seed []byte) (map[string]interface{}, error) {
	raw, _ := base64.StdEncoding.DecodeString(rawB64)
	sig, _ := login.SignString(string(raw), seed)
	return d.w.ReceiveEvent(aid, raw, sig)
}

// approved sends the organisation's inception and its approval.
func (d *delegation) approved(t *testing.T) {
	t.Helper()
	for _, ev := range []string{d.icpB64, d.approvalB64} {
		if _, err := d.send(d.org, ev, d.orgSeed); err != nil {
			t.Fatal(err)
		}
	}
}

func (d *delegation) interaction(t *testing.T, name, aid string, i int) string {
	t.Helper()
	ixn, err := d.e.Interact(name, []interface{}{map[string]interface{}{"d": fmt.Sprintf("Eseal%s%d", aid[:4], i)}})
	if err != nil {
		t.Fatal(err)
	}
	return ixn.RawBytesB64
}

// A delegate is witnessed only while its delegator is.
func TestADelegateIsWitnessedOnlyWhileItsDelegatorIs(t *testing.T) {
	d := newDelegation(t)
	d.approved(t)
	if _, err := d.send(d.delegate, d.dipB64, d.delegateSeed); err != nil {
		t.Fatal(err)
	}
	if _, err := d.send(d.delegate, d.interaction(t, d.delegate, d.delegate, 1), d.delegateSeed); err != nil {
		t.Fatal(err)
	}
	meta, _ := d.w.Store.GetContactMeta(d.org)
	meta.WitnessingFor = false
	d.w.Store.SaveContactMeta(*meta)
	if _, err := d.send(d.delegate, d.interaction(t, d.delegate, d.delegate, 2), d.delegateSeed); err == nil {
		t.Fatal("a delegate was witnessed after its delegator stopped being")
	}
	if dm, _ := d.w.Store.GetContactMeta(d.delegate); dm != nil && dm.WitnessingFor {
		t.Fatal("the delegate is still enrolled")
	}
}

// Withdrawing from an identity withdraws from the identities it delegated.
func TestWithdrawingFromADelegatorDropsItsDelegates(t *testing.T) {
	d := newDelegation(t)
	d.approved(t)
	if _, err := d.send(d.delegate, d.dipB64, d.delegateSeed); err != nil {
		t.Fatal(err)
	}
	notDesignated := func(string, string) (bool, error) { return false, nil }
	if err := d.w.ReceiveWithdrawalConfirmation(WithdrawalConfirmation{ControllerAID: d.org, WitnessKey: d.wkey, RotationRawB64: "cut"}, notDesignated); err != nil {
		t.Fatal(err)
	}
	if dm, _ := d.w.Store.GetContactMeta(d.delegate); dm != nil && dm.WitnessingFor {
		t.Fatal("the delegate is still witnessed after the witness withdrew from its delegator")
	}
}

// The operator can switch delegates off, or cap them per delegator.
func TestDelegatesCanBeSwitchedOffOrCapped(t *testing.T) {
	for _, c := range []struct {
		name, on, max string
		accepted      bool
	}{{"off", "off", "", false}, {"capped at none", "", "0", false}, {"capped at one", "", "1", true}, {"default", "", "", true}} {
		t.Run(c.name, func(t *testing.T) {
			d := newDelegation(t)
			d.w.Store.SetConfig(ConfigDelegates, c.on)
			d.w.Store.SetConfig(ConfigDelegatesMax, c.max)
			d.approved(t)
			_, err := d.send(d.delegate, d.dipB64, d.delegateSeed)
			if (err == nil) != c.accepted {
				t.Fatalf("accepted=%v, want %v (%v)", err == nil, c.accepted, err)
			}
		})
	}
}

// An event already held is answered with its receipt; something else at the
// same place is a conflict.
func TestAnEventAlreadyHeldIsAnsweredWithItsReceipt(t *testing.T) {
	d := newDelegation(t)
	first, err := d.send(d.org, d.icpB64, d.orgSeed)
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.send(d.org, d.icpB64, d.orgSeed)
	if err != nil {
		t.Fatalf("an event already held was refused: %v", err)
	}
	if again["cesr_signature"] != first["cesr_signature"] || again["event_said"] != first["event_said"] {
		t.Fatal("an event already held was not answered with its receipt")
	}
	other := newDelegation(t)
	if _, err := d.send(d.org, other.icpB64, other.orgSeed); err == nil || !strings.Contains(err.Error(), "duplicate_sequence") && !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("a conflicting event at a place already held: %v", err)
	}
}

// A witness is sent only what it does not hold yet.
func TestOnlyWhatAWitnessLacksIsSent(t *testing.T) {
	d := newDelegation(t)
	sender, mc := testService(t)
	mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", OobiURL: "http://w.test", IsWitness: true}
	_ = sender.Store.SaveContactMeta(ContactMeta{ContactAID: "EWitness", WitnessKey: d.wkey})
	posts := 0
	sender.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		posts++
		var req struct {
			AID   string `json:"aid"`
			Event string `json:"event_b64"`
			Sig   string `json:"cesr_signature"`
		}
		_ = json.Unmarshal(body, &req)
		raw, _ := base64.StdEncoding.DecodeString(req.Event)
		return d.w.ReceiveEvent(req.AID, raw, req.Sig)
	}
	sender.FetchTip = func(_ context.Context, url string) (TipAnswer, error) {
		_, nonce, _ := strings.Cut(url, "?nonce=")
		return d.w.KelTip(d.org, nonce)
	}
	signed := func(rawB64 string) SignedEvent {
		raw, _ := base64.StdEncoding.DecodeString(rawB64)
		sig, _ := login.SignString(string(raw), d.orgSeed)
		return SignedEvent{RawBytesB64: rawB64, CesrSignature: sig}
	}
	log := []SignedEvent{signed(d.icpB64), signed(d.approvalB64)}
	sender.BringUpToDate(context.Background(), d.org, log, []string{d.wkey}, 1)
	if posts != 2 {
		t.Fatalf("%d events were sent to a witness holding none", posts)
	}
	log = append(log, signed(d.interaction(t, "org", d.org, 1)))
	posts = 0
	sender.BringUpToDate(context.Background(), d.org, log, []string{d.wkey}, 1)
	if posts != 1 {
		t.Fatalf("%d events were sent to a witness lacking one", posts)
	}
}

// A bootstrap witness's address is pinned: a contact naming its key does not
// redirect where it is asked.
func TestABootstrapWitnessCannotBeRedirected(t *testing.T) {
	s, mc := testService(t)
	wpub, _, _ := ed25519.GenerateKey(rand.Reader)
	wkey := iacrypto.NonTransferableAIDQB64(wpub)
	was := BootstrapWitnesses
	BootstrapWitnesses = func() []BootstrapWitness {
		return []BootstrapWitness{{AID: "EBoot", WitnessKey: wkey, URL: "https://boot.test"}}
	}
	t.Cleanup(func() { BootstrapWitnesses = was })
	mc.contacts["EElsewhere"] = store.ContactRecord{AID: "EElsewhere", OobiURL: "http://elsewhere.test", IsWitness: true}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EElsewhere", WitnessKey: wkey})
	if got := s.designatedTargets([]string{wkey})[wkey]; got.URL != "https://boot.test" {
		t.Fatalf("a contact redirected a bootstrap witness to %q", got.URL)
	}
}

// A tip answer is believed only for the identity, the nonce and the witness
// it was asked of.
func TestATipAnswerIsBelievedOnlyAsAsked(t *testing.T) {
	d := newDelegation(t)
	d.approved(t)
	a, err := d.w.KelTip(d.org, "n-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := heldTipOf(d.org, d.wkey, "n-1", a); !ok {
		t.Fatal("a good answer was not believed")
	}
	if _, ok := heldTipOf(d.org, d.wkey, "n-2", a); ok {
		t.Fatal("an answer to another question was believed")
	}
	if _, ok := heldTipOf(d.delegate, d.wkey, "n-1", a); ok {
		t.Fatal("an answer about another identity was believed")
	}
	other := newDelegation(t)
	if _, ok := heldTipOf(d.org, other.wkey, "n-1", a); ok {
		t.Fatal("an answer was believed as another witness's")
	}
	a.SN++
	if _, ok := heldTipOf(d.org, d.wkey, "n-1", a); ok {
		t.Fatal("an altered answer was believed")
	}
}

// What a witness signs about its tip is fixed byte for byte: every witness
// implementation signs exactly this, or its answers are never believed.
func TestTheTipStatementIsFixed(t *testing.T) {
	if got := TipStatement("EAid", "n-1", 17, "ESaid"); got != "witness-kel-tip/v1\nEAid\nn-1\n17\nESaid" {
		t.Fatalf("the tip statement is %q", got)
	}
}

// A witness whose tip is not known, such as an older witness with no tip
// route, is sent nothing rather than the whole log.
func TestAWitnessWithNoTipIsSentNothing(t *testing.T) {
	d := newDelegation(t)
	sender, mc := testService(t)
	mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", OobiURL: "http://w.test", IsWitness: true}
	_ = sender.Store.SaveContactMeta(ContactMeta{ContactAID: "EWitness", WitnessKey: d.wkey})
	posts := 0
	sender.PostEvent = func(context.Context, string, []byte) (map[string]interface{}, error) {
		posts++
		return nil, fmt.Errorf("not reached")
	}
	sender.FetchTip = func(context.Context, string) (TipAnswer, error) {
		return TipAnswer{}, fmt.Errorf("witness GET 404")
	}
	raw, _ := base64.StdEncoding.DecodeString(d.icpB64)
	sig, _ := login.SignString(string(raw), d.orgSeed)
	sender.BringUpToDate(context.Background(), d.org, []SignedEvent{{RawBytesB64: d.icpB64, CesrSignature: sig}}, []string{d.wkey}, 1)
	if posts != 0 {
		t.Fatalf("%d events were sent to a witness whose tip is not known", posts)
	}
}

// A delegator whose agreement did not ask for its delegates has none
// witnessed.
func TestADelegatorThatDidNotAskHasNoDelegatesWitnessed(t *testing.T) {
	d := newDelegation(t)
	agreeToWitness(t, d.w, d.mc, d.org, false)
	d.approved(t)
	if _, err := d.send(d.delegate, d.dipB64, d.delegateSeed); err == nil {
		t.Fatal("a delegate was witnessed for a delegator that did not ask")
	}
}

// A witness request says whether it asks for the requester's delegates to be
// witnessed, as this agent decides.
func TestAWitnessRequestSaysWhetherItCoversDelegates(t *testing.T) {
	for _, asks := range []bool{true, false} {
		s, mc := testService(t)
		mc.contacts["EPeer"] = store.ContactRecord{AID: "EPeer", OobiURL: "http://peer.test", Status: "accepted", ContactCategory: "trusted"}
		s.AskToCoverDelegates = func() bool { return asks }
		var sent map[string]interface{}
		s.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
			_ = json.Unmarshal(body, &sent)
			return map[string]interface{}{}, nil
		}
		if err := s.SendWitnessRequest(context.Background(), "EPeer"); err != nil {
			t.Fatal(err)
		}
		if sent["covers_delegates"] != asks {
			t.Fatalf("a request that asks=%v says %v", asks, sent["covers_delegates"])
		}
	}
}
