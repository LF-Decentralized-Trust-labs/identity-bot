package keriengine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// An app's keys: generated here and never remembered, so the engine's
// installed signer cannot sign with them. Only the test, standing in for the
// app, can.
func appKey(t *testing.T) *keri.SoftwareSigner {
	t.Helper()
	s, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pubOf(t *testing.T, s keri.Signer) string {
	t.Helper()
	p, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func digestOf(t *testing.T, s keri.Signer) string {
	t.Helper()
	d, err := keri.NextDigest(pubOf(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// signAt is s's indexed signature over raw at index, opening ondex of the
// prior commitment (ondex < 0: current list only).
func signAt(t *testing.T, s keri.Signer, raw []byte, index, ondex int) string {
	t.Helper()
	sig, err := s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	at := keri.SignaturePlace{Index: index, Ondex: ondex, CurrentOnly: ondex < 0}
	if ondex < 0 {
		at.Ondex = 0
	}
	qb64, err := keri.EncodeIndexedSignature(sig, at)
	if err != nil {
		t.Fatal(err)
	}
	return qb64
}

var one = json.RawMessage(`"1"`)

// appHeld founds an identity whose keys only the test holds, through prepare
// and commit, and returns the engine and the three keys k0, k1, k2.
func appHeld(t *testing.T) (*Engine, string, []*keri.SoftwareSigner) {
	t.Helper()
	e := New()
	ks := []*keri.SoftwareSigner{appKey(t), appKey(t), appKey(t), appKey(t)}
	p, err := e.Prepare(PrepareRequest{Ilk: "icp", Keys: []string{pubOf(t, ks[0])}, Kt: one,
		Next: []string{digestOf(t, ks[1])}, Nt: one})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.GetKel(p.Hint.I); err == nil {
		t.Fatal("preparing a founding added it")
	}
	res, err := e.Commit("", p.Raw, []string{signAt(t, ks[0], p.Raw, 0, 0)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "recorded" || res.AID != p.Hint.I {
		t.Fatalf("the founding was not recorded: %+v", res)
	}
	return e, res.AID, ks
}

// signedLog is the engine's log of aid as messages with their signatures.
func signedLog(t *testing.T, e *Engine, aid string) [][]byte {
	t.Helper()
	kel, err := e.GetKel(aid)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for i, b := range kel.RawEventsB64 {
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			t.Fatal(err)
		}
		m, err := signedMessage(raw, kel.Signatures[i])
		if err != nil {
			t.Fatalf("event %d is held without signatures", i)
		}
		out = append(out, m)
	}
	return out
}

// A rotation whose key nobody here holds is not added: it would have gone
// into the log unsigned, and before this it did.
func TestAnUnsignedRotationIsRefused(t *testing.T) {
	e, aid, ks := appHeld(t)
	if _, err := e.Rotate(drivers.RotationRequest{Name: aid, NewPublicKey: pubOf(t, ks[1]),
		NewNextPublicKey: pubOf(t, ks[2])}); err == nil {
		t.Fatal("a rotation nobody signed was added")
	}
	kel, _ := e.GetKel(aid)
	if kel.EventCount != 1 {
		t.Fatalf("the log has %d events", kel.EventCount)
	}
}

// An identity whose keys the app holds rotates and interacts: the engine
// builds each event, adds nothing until it is signed, and the log it ends with
// is one keri-go verifies, signatures and all.
func TestAnAppHeldIdentityRotatesAndInteracts(t *testing.T) {
	e, aid, ks := appHeld(t)

	rot := PrepareRequest{Name: aid, Ilk: "rot", Keys: []string{pubOf(t, ks[1])}, Kt: one,
		Next: []string{digestOf(t, ks[2])}, Nt: one, After: &Place{SN: 0, SAID: aid}}
	p1, err := e.Prepare(rot)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := e.Prepare(rot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1.Raw, p2.Raw) {
		t.Fatal("preparing the same rotation twice gave different bytes")
	}
	if kel, _ := e.GetKel(aid); kel.EventCount != 1 {
		t.Fatal("preparing a rotation added it")
	}

	// Signed by the wrong key: nothing is written.
	if _, err := e.Commit(aid, p1.Raw, []string{signAt(t, ks[2], p1.Raw, 0, 0)}, nil); err == nil {
		t.Fatal("a rotation signed by a key that is not the one it reveals was added")
	}
	if kel, _ := e.GetKel(aid); kel.EventCount != 1 {
		t.Fatal("a refused commit wrote something")
	}

	var kept []drivers.KELKeep
	keep := func(k drivers.KELKeep) error { kept = append(kept, k); return nil }
	res, err := e.Commit(aid, p1.Raw, []string{signAt(t, ks[1], p1.Raw, 0, 0)}, keep)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "recorded" || len(kept) != 1 || len(kept[0].Signatures) != 1 {
		t.Fatalf("the rotation was not recorded and kept with its signature: %+v %+v", res, kept)
	}
	again, err := e.Commit(aid, p1.Raw, []string{signAt(t, ks[1], p1.Raw, 0, 0)}, nil)
	if err != nil || again.Status != "already_recorded" {
		t.Fatalf("committing the same rotation again: %+v %v", again, err)
	}

	ixn, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "ixn",
		Anchors: []json.RawMessage{json.RawMessage(`{"d":"EAnchoredThing"}`)},
		After:   &Place{SN: 1, SAID: res.SAID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Commit(aid, ixn.Raw, []string{signAt(t, ks[0], ixn.Raw, 0, -1)}, nil); err == nil {
		t.Fatal("an interaction signed by the key rotated away from was added")
	}
	if _, err := e.Commit(aid, ixn.Raw, []string{signAt(t, ks[1], ixn.Raw, 0, -1)}, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := keri.ValidateSignedKEL(signedLog(t, e, aid)); err != nil {
		t.Fatalf("the log the engine holds does not verify: %v", err)
	}
}

// A commit built on a tip that has since moved is refused, and so is a
// prepare that names an event that is not the tip.
func TestACommitOnAMovedTipIsRefused(t *testing.T) {
	e, aid, ks := appHeld(t)
	anchor := func(d string) []json.RawMessage { return []json.RawMessage{json.RawMessage(`{"d":"` + d + `"}`)} }
	a, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "ixn", Anchors: anchor("EA"), After: &Place{SN: 0, SAID: aid}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "ixn", Anchors: anchor("EB"), After: &Place{SN: 0, SAID: aid}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Commit(aid, a.Raw, []string{signAt(t, ks[0], a.Raw, 0, -1)}, nil); err != nil {
		t.Fatal(err)
	}
	var moved *ErrTipMoved
	if _, err := e.Commit(aid, b.Raw, []string{signAt(t, ks[0], b.Raw, 0, -1)}, nil); !errors.As(err, &moved) {
		t.Fatalf("a second interaction at a taken place was not refused as tip_moved: %v", err)
	}
	if _, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "ixn", Anchors: anchor("EC"),
		After: &Place{SN: 0, SAID: aid}}); !errors.As(err, &moved) || moved.Tip.SN != 1 {
		t.Fatalf("an interaction prepared after an event that is not the tip: %v", err)
	}
}

// A rotation whose keys cannot open the commitment is refused at prepare,
// before anybody is asked to sign it.
func TestARotationToAnUncommittedKeyIsRefusedAtPrepare(t *testing.T) {
	e, aid, ks := appHeld(t)
	var nc *ErrNotCommitted
	if _, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "rot", Keys: []string{pubOf(t, ks[2])}, Kt: one,
		Next: []string{digestOf(t, ks[3])}, Nt: one}); !errors.As(err, &nc) {
		t.Fatalf("a rotation to a key nobody committed to: %v", err)
	}
}

// A recovery rotation after a kept interaction supersedes the interactions
// after it, which are kept aside, and the log that results verifies.
func TestARecoveryRotationSupersedesTheInteractionsAfterIt(t *testing.T) {
	e, aid, ks := appHeld(t)
	var places []Place
	after := Place{SN: 0, SAID: aid}
	for _, d := range []string{"EKept", "EThief1", "EThief2"} {
		p, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "ixn",
			Anchors: []json.RawMessage{json.RawMessage(`{"d":"` + d + `"}`)}, After: &after})
		if err != nil {
			t.Fatal(err)
		}
		res, err := e.Commit(aid, p.Raw, []string{signAt(t, ks[0], p.Raw, 0, -1)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		after = Place{SN: res.SN, SAID: res.SAID}
		places = append(places, after)
	}

	rot, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "rot", Keys: []string{pubOf(t, ks[1])}, Kt: one,
		Next: []string{digestOf(t, ks[2])}, Nt: one, After: &places[0]})
	if err != nil {
		t.Fatal(err)
	}
	var kept []drivers.KELKeep
	res, err := e.Commit(aid, rot.Raw, []string{signAt(t, ks[1], rot.Raw, 0, 0)},
		func(k drivers.KELKeep) error { kept = append(kept, k); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if res.SN != 2 || len(res.Superseded) != 2 || kept[0].Supersedes != 2 {
		t.Fatalf("the recovery rotation did not supersede the two interactions after the kept one: %+v %+v", res, kept)
	}
	kel, _ := e.GetKel(aid)
	if kel.EventCount != 3 {
		t.Fatalf("the log has %d events, not founding, kept interaction and rotation", kel.EventCount)
	}
	if _, err := keri.ValidateSignedKEL(signedLog(t, e, aid)); err != nil {
		t.Fatalf("the recovered log does not verify: %v", err)
	}

	// A second rotation at the rotation's place is duplicity, kept as evidence.
	other, err := keri.BuildRotation(keri.RotationInput{Prefix: aid, Keys: []string{pubOf(t, ks[1])},
		PriorSAID: places[0].SAID, SN: 2, NextDigests: []string{digestOf(t, ks[3])}})
	if err != nil {
		t.Fatal(err)
	}
	var taken *ErrPlaceTaken
	if _, err := e.Commit(aid, other, []string{signAt(t, ks[1], other, 0, 0)}, nil); !errors.As(err, &taken) || !taken.Kept {
		t.Fatalf("a second rotation at a rotation's place: %v", err)
	}
	if ev, _ := e.EvidenceOf(aid); len(ev) != 1 {
		t.Fatalf("the duplicitous rotation was not kept as evidence: %d", len(ev))
	}
}

// An event with several signers waits for the rest. Two candidates may wait at
// one place; the one whose signatures meet both thresholds is added and the
// other is kept as evidence. Expiry drops only the hold.
func TestAnEventWithSeveralSignersWaitsForThem(t *testing.T) {
	e := New()
	a0, a1, b0, b1 := appKey(t), appKey(t), appKey(t), appKey(t)
	two := json.RawMessage(`"2"`)
	p, err := e.Prepare(PrepareRequest{Ilk: "icp", Keys: []string{pubOf(t, a0), pubOf(t, b0)}, Kt: two,
		Next: []string{digestOf(t, a1), digestOf(t, b1)}, Nt: two})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Commit("", p.Raw, []string{signAt(t, a0, p.Raw, 0, 0), signAt(t, b0, p.Raw, 1, 1)}, nil); err != nil {
		t.Fatal(err)
	}
	aid := p.Hint.I
	after := &Place{SN: 0, SAID: aid}
	rotTo := func(next []string) *Prepared {
		r, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "rot", Keys: []string{pubOf(t, a1), pubOf(t, b1)},
			Kt: two, Next: next, Nt: two, After: after})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := rotTo([]string{digestOf(t, appKey(t)), digestOf(t, appKey(t))})
	second := rotTo([]string{digestOf(t, appKey(t)), digestOf(t, appKey(t))})

	e.clock = func() time.Time { return time.Unix(1000, 0) }
	res, err := e.Commit(aid, first.Raw, []string{signAt(t, a1, first.Raw, 0, 0)}, nil)
	if err != nil || res.Status != "waiting_for_signatures" || len(res.Signed) != 1 || res.Keys != 2 {
		t.Fatalf("the first owner's signature: %+v %v", res, err)
	}
	if res, err := e.Commit(aid, second.Raw, []string{signAt(t, b1, second.Raw, 1, 1)}, nil); err != nil || res.Status != "waiting_for_signatures" {
		t.Fatalf("a second candidate at the same place: %+v %v", res, err)
	}
	if kel, _ := e.GetKel(aid); kel.EventCount != 1 {
		t.Fatal("an event waiting for signatures was added")
	}
	res, err = e.Commit(aid, first.Raw, []string{signAt(t, b1, first.Raw, 1, 1)}, nil)
	if err != nil || res.Status != "recorded" {
		t.Fatalf("both owners signed and it was not recorded: %+v %v", res, err)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].SAID == res.SAID {
		t.Fatalf("the other candidate was not kept as evidence: %+v", res.Evidence)
	}
	if _, err := keri.ValidateSignedKEL(signedLog(t, e, aid)); err != nil {
		t.Fatalf("the two-owner log does not verify: %v", err)
	}

	// Expiry drops the hold and nothing else.
	after = &Place{SN: 1, SAID: res.SAID}
	c1, d1 := appKey(t), appKey(t)
	_ = c1
	_ = d1
	ixn, err := e.Prepare(PrepareRequest{Name: aid, Ilk: "ixn",
		Anchors: []json.RawMessage{json.RawMessage(`{"d":"EX"}`)}, After: after})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := e.Commit(aid, ixn.Raw, []string{signAt(t, a1, ixn.Raw, 0, -1)}, nil); err != nil || res.Status != "waiting_for_signatures" {
		t.Fatalf("one owner's interaction signature: %+v %v", res, err)
	}
	e.clock = func() time.Time { return time.Unix(1000, 0).Add(defaultHoldFor + time.Second) }
	if h := e.heldAt(mustGet(t, e, aid), 2, ixn.Hint.D); h != nil {
		t.Fatal("an expired candidate was still held")
	}
	if kel, _ := e.GetKel(aid); kel.EventCount != 2 {
		t.Fatal("expiry changed the log")
	}
}

func mustGet(t *testing.T, e *Engine, aid string) *identity {
	t.Helper()
	id, err := e.state.get(aid)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A log reloaded with an event an earlier version added unsigned is not
// extended until that event is signed.
func TestAnUnsignedEventStopsTheLogUntilItIsSigned(t *testing.T) {
	e, aid, ks := appHeld(t)
	kel, _ := e.GetKel(aid)
	restored := New()
	if _, err := restored.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: aid,
		LastSAID: aid, KEL: kel.KEL, RawEventsB64: kel.RawEventsB64}); err != nil {
		t.Fatal(err)
	}
	p, err := restored.Prepare(PrepareRequest{Name: aid, Ilk: "ixn",
		Anchors: []json.RawMessage{json.RawMessage(`{"d":"EY"}`)}, After: &Place{SN: 0, SAID: aid}})
	if err != nil {
		t.Fatal(err)
	}
	var unsigned *ErrUnsignedHistory
	if _, err := restored.Commit(aid, p.Raw, []string{signAt(t, ks[0], p.Raw, 0, -1)}, nil); !errors.As(err, &unsigned) {
		t.Fatalf("an event was added after one held unsigned: %v", err)
	}
	// Reloaded with its signature, it extends.
	again := New()
	if _, err := again.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: aid, LastSAID: aid,
		KEL: kel.KEL, RawEventsB64: kel.RawEventsB64, Signatures: kel.Signatures}); err != nil {
		t.Fatal(err)
	}
	if _, err := again.Commit(aid, p.Raw, []string{signAt(t, ks[0], p.Raw, 0, -1)}, nil); err != nil {
		t.Fatal(err)
	}
}

// A signature that does not verify is refused with the event, even beside
// signatures that meet the threshold, and nothing is kept: a log this engine
// publishes carries no junk somebody sent with it. A commit of an event
// already recorded with junk added is refused the same way.
func TestASignatureThatDoesNotVerifyIsNeverKept(t *testing.T) {
	e := New()
	a, b, n := appKey(t), appKey(t), appKey(t)
	p, err := e.Prepare(PrepareRequest{Ilk: "icp", Keys: []string{pubOf(t, a), pubOf(t, b)}, Kt: one,
		Next: []string{digestOf(t, n)}, Nt: one})
	if err != nil {
		t.Fatal(err)
	}
	junk := signAt(t, n, p.Raw, 1, 1) // made with a key that is not k[1]
	var na *ErrNotAuthorised
	if _, err := e.Commit("", p.Raw, []string{signAt(t, a, p.Raw, 0, 0), junk}, nil); !errors.As(err, &na) || !na.BadSignature {
		t.Fatalf("a founding with a signature that does not verify: %v", err)
	}
	if _, err := e.Commit("", p.Raw, []string{signAt(t, a, p.Raw, 0, 0)}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Commit("", p.Raw, []string{junk}, nil); err == nil {
		t.Fatal("junk was accepted beside an event already recorded")
	}
	kel, _ := e.GetKel(p.Hint.I)
	if len(kel.Signatures[0]) != 1 {
		t.Fatalf("the founding is held with %d signatures", len(kel.Signatures[0]))
	}
}

// A rotation held without its signature is signed by the engine's own signer
// only where it was marked unsigned when this version first ran. One stored
// unsigned since, which whoever could write the store may have composed, is
// never signed here, and the log is not extended past it.
func TestAnUnmarkedUnsignedRotationIsNeverSignedHere(t *testing.T) {
	k0, _ := testSigner(true)
	k1, _ := testSigner(true)
	k2, _ := testSigner(true)
	e := New()
	inc, err := e.CreateInceptionNamed(pubOf(t, k0), pubOf(t, k1), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Rotate(drivers.RotationRequest{Name: "a", NewPublicKey: pubOf(t, k1), NewNextPublicKey: pubOf(t, k2)}); err != nil {
		t.Fatal(err)
	}
	kel, _ := e.GetKel("a")
	sigs := [][]string{kel.Signatures[0], nil} // the rotation stored unsigned
	ixn := func(e *Engine) error {
		_, err := e.Interact(inc.AID, []interface{}{map[string]string{"d": "EZ"}})
		return err
	}
	for _, marked := range []bool{false, true} {
		r := New()
		if _, err := r.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: inc.AID, LastSAID: kel.KEL[1]["d"].(string),
			KEL: kel.KEL, RawEventsB64: kel.RawEventsB64, Signatures: sigs,
			UnsignedAtUpgrade: []bool{false, marked}}); err != nil {
			t.Fatal(err)
		}
		err := ixn(r)
		var unsigned *ErrUnsignedHistory
		if marked && err != nil {
			t.Fatalf("a rotation marked unsigned at upgrade was not signed and the log not extended: %v", err)
		}
		if !marked && !errors.As(err, &unsigned) {
			t.Fatalf("an unmarked unsigned rotation was signed here: %v", err)
		}
	}
}
