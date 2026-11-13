package anchored

import (
	"errors"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/measurementlist"
)

var now = t0.Add(24 * time.Hour)

// published has one list of that sequence issued, sealed and witnessed.
func published(p *publisher, seq int) (string, int) {
	if p.registry == "" {
		p.foundRegistry()
	}
	return p.issue(listSpec{sequence: seq, expires: t0.Add(60 * 24 * time.Hour), images: defaultImages(meas(byte(seq)))})
}

func accept(t *testing.T, p *publisher, f Floors) *Result {
	t.Helper()
	res, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), f, now)
	if err != nil {
		t.Fatalf("a good bundle was refused: %v", err)
	}
	return res
}

func refuse(t *testing.T, why string, want error, b *Bundle, pin Pin, replies []TipReply, f Floors) error {
	t.Helper()
	res, err := Verify(b, pin, replies, f, now)
	if err == nil {
		t.Fatalf("ACCEPTED (%s): list %+v", why, res.List)
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("refused (%s), but with %v and not %v", why, err, want)
	}
	return err
}

func TestAPublishedListIsAccepted(t *testing.T) {
	p := onekey(t)
	cred, _ := published(p, 7)
	res := accept(t, p, Floors{})
	if res.CredentialSAID != cred || res.List.Sequence != 7 || len(res.List.Measurements("individual")) != 1 {
		t.Fatalf("accepted %+v", res)
	}
	if res.Tip != p.tip() {
		t.Fatalf("the tip is %+v, expected %+v", res.Tip, p.tip())
	}
	// the bundle survives its own encoding
	enc, err := p.bundle().Encode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBundle(enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(b, p.pin(), p.answers(p.tip(), 2), Floors{}, now); err != nil {
		t.Fatalf("a bundle read back was refused: %v", err)
	}
}

func TestTheNewestListNotWithdrawnIsTheAnswer(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	c8, _ := published(p, 8)
	if got := accept(t, p, Floors{}).List.Sequence; got != 8 {
		t.Fatalf("the answer is list %d, not the newest", got)
	}
	p.revoke(c8)
	if got := accept(t, p, Floors{}).List.Sequence; got != 7 {
		t.Fatalf("with list 8 withdrawn the answer is list %d", got)
	}
	p.revoke(func() string { s, _ := keri.VerifyCredential(p.creds[0]); return s.SAID }())
	refuse(t, "every list withdrawn", ErrNoList, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
}

func TestAnAnchorThatIsNotThereOrNotWhole(t *testing.T) {
	t.Run("an issuance the key history never sealed", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		b := p.bundle()
		b.KEL = b.KEL[:len(b.KEL)-1] // the seal of the issuance is the last event
		refuse(t, "unanchored", ErrUnsealed, b, p.pin(), p.answers(tipAt(p, len(b.KEL)-1), 2), Floors{})
	})
	t.Run("a seal with no event behind it", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		b := p.bundle()
		b.TEL = b.TEL[:len(b.TEL)-1]
		refuse(t, "seal not matched in the bundle", ErrWithheld, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a withdrawal withheld: its seal is in the history", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		c8, _ := published(p, 8)
		p.revoke(c8)
		b := p.bundle()
		b.TEL = b.TEL[:len(b.TEL)-1] // the rev
		refuse(t, "rev withheld, list 8 shown as current", ErrWithheld, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a seal naming the wrong event of the credential", func(t *testing.T) {
		p := onekey(t)
		p.foundRegistry()
		p.wrongSeal = true
		published(p, 7)
		refuse(t, "credential seal names another digest", ErrUnsealed, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a credential the registry never issued", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		q := onekey(t)
		q.registry = p.registry
		q.schema = p.schema
		q.issue(listSpec{sequence: 9, expires: t0.Add(1000 * time.Hour), images: defaultImages(meas(9))})
		b := p.bundle()
		b.Credentials = append(b.Credentials, q.creds[0])
		refuse(t, "a credential with no issuance in the history", nil, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("anchors that are not seals of the registry's events are the identity's own business", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		p.seal([]byte(`{"handover":"owners/v1","d":"` + strings.Repeat("a", 64) + `"}`))
		owner := "E" + strings.Repeat("O", 43)
		p.seal(sealOf(owner, 0, owner)) // the owner seal of a box-founded identity
		accept(t, p, Floors{})
	})
	t.Run("a seal of an event the bundle does not hold, in the shape of an issuance", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		p.seal(sealOf("E"+strings.Repeat("C", 43), 0, "E"+strings.Repeat("D", 43)))
		refuse(t, "a hidden issuance", ErrWithheld, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a seal of a revocation of a credential, hidden", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		c, _ := keri.VerifyCredential(p.creds[0])
		p.seal(sealOf(c.SAID, 1, "E"+strings.Repeat("D", 43)))
		refuse(t, "a hidden revocation", ErrWithheld, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("the same seal twice", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		c, _ := keri.VerifyCredential(p.creds[0])
		ie, _ := keri.VerifyTELEvent(p.tel[1])
		p.seal(sealOf(c.SAID, 0, ie.SAID))
		refuse(t, "a seal repeated", ErrForeignSeal, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
}

func TestWitnessing(t *testing.T) {
	t.Run("receipts below the witness threshold", func(t *testing.T) {
		p := onekey(t)
		p.receipts = 1 // the threshold is 2
		published(p, 7)
		refuse(t, "one receipt of two needed", ErrNotWitnessed, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("receipts from witnesses the identity did not designate", func(t *testing.T) {
		p := onekey(t)
		p.rogue = []member{newMember(t, false), newMember(t, false), newMember(t, false)}
		published(p, 7)
		refuse(t, "receipts by strangers", ErrNotWitnessed, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("an identity with no witnesses is vouched for by nobody", func(t *testing.T) {
		k, n := newMember(t, true), newMember(t, true)
		p := newPublisher(t, found{keys: []member{k}, next: []member{n}, kt: `"1"`, nt: `"1"`, witnesses: 0, toad: 0})
		published(p, 7)
		refuse(t, "no witnesses", ErrNotWitnessed, p.bundle(), p.pin(), nil, Floors{})
	})
}

func TestSigning(t *testing.T) {
	three := func(t *testing.T) (*publisher, []member, []member) {
		k := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		n := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		return newPublisher(t, found{keys: k, next: n, kt: `"2"`, nt: `"2"`, witnesses: 3, toad: 2}), k, n
	}
	t.Run("two of three sign, and a rotation keeps the threshold", func(t *testing.T) {
		p, _, n := three(t)
		published(p, 7)
		// members 0 and 1 of the next set take over, each opening its own place
		next2 := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		p.rotate(n, next2, `"2"`, `"2"`, n[:2], []place{{0, 0}, {1, 1}})
		published(p, 8)
		if got := accept(t, p, Floors{}).List.Sequence; got != 8 {
			t.Fatalf("list %d", got)
		}
	})
	t.Run("a rotation signed with the second key opening the first place, by dual index", func(t *testing.T) {
		p, _, n := three(t)
		published(p, 7)
		next2 := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		// keys listed in a different order: n[2], n[0], n[1] open places 2, 0, 1
		p.rotate([]member{n[2], n[0], n[1]}, next2, `"2"`, `"2"`, []member{n[2], n[0]}, []place{{0, 2}, {1, 0}})
		published(p, 8)
		accept(t, p, Floors{})
	})
	t.Run("signed below the threshold", func(t *testing.T) {
		p, _, _ := three(t)
		p.signWith = 1
		published(p, 7)
		refuse(t, "one signer of two", ErrBadHistory, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a rotation that meets kt but not the prior next threshold", func(t *testing.T) {
		p, _, n := three(t)
		published(p, 7)
		next2 := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		// every committed key listed, kt 1 and met by one signature, but one
		// signature opens one commitment of the two the prior event needs
		p.rotate(n, next2, `"1"`, `"2"`, n[:1], []place{{0, 0}})
		published(p, 8)
		refuse(t, "kt met, prior nt not", ErrBadHistory, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a rotation presenting keys that were not committed to", func(t *testing.T) {
		p, _, _ := three(t)
		published(p, 7)
		x := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		p.rotate(x, x, `"2"`, `"2"`, x[:2], []place{{0, 0}, {1, 1}})
		published(p, 8)
		refuse(t, "keys not pre-committed", ErrBadHistory, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("signed by keys that were rotated out", func(t *testing.T) {
		p, k, n := three(t)
		published(p, 7)
		next2 := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		p.rotate(n, next2, `"2"`, `"2"`, n[:2], []place{{0, 0}, {1, 1}})
		p.cur = k // a thief holding the old keys
		published(p, 8)
		refuse(t, "old keys sealing a list", ErrBadHistory, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("weighted thresholds", func(t *testing.T) {
		k := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		n := []member{newMember(t, true), newMember(t, true), newMember(t, true)}
		p := newPublisher(t, found{keys: k, next: n, kt: `["1/2","1/2","1/4"]`, nt: `["1/2","1/2","1/4"]`, witnesses: 3, toad: 2})
		p.signWith = 2 // keys 0 and 1 weigh 1
		published(p, 7)
		accept(t, p, Floors{})
	})
}

func TestTheListIsTheOnePinned(t *testing.T) {
	t.Run("another publisher's bundle", func(t *testing.T) {
		p, q := onekey(t), onekey(t)
		published(p, 7)
		published(q, 7)
		refuse(t, "a list of another publisher", ErrWrongPublisher, q.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("another schema", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		pin := p.pin()
		pin.SchemaSAID = "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		refuse(t, "a list under another schema", ErrBadList, p.bundle(), pin, p.answers(p.tip(), 2), Floors{})
	})
	t.Run("another registry", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		pin := p.pin()
		pin.Registry = "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		b := p.bundle()
		b.Registry = pin.Registry
		refuse(t, "another registry", nil, b, pin, p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a registry that may have backers", func(t *testing.T) {
		p := onekey(t)
		vcp, _ := keri.BuildRegistryInception(keri.RegistryInput{Issuer: p.aid, Nonce: "0AB2dnZ2dnZ2dnZ2dnZ2dnZ2"})
		ev, _ := keri.VerifyTELEvent(vcp)
		p.registry = ev.SAID
		p.tel = append(p.tel, vcp)
		p.seal(sealOf(ev.SAID, 0, ev.SAID))
		published(p, 7)
		refuse(t, "no NB trait", ErrBadRegistry, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("another inception", func(t *testing.T) {
		p, q := onekey(t), onekey(t)
		published(p, 7)
		pin := p.pin()
		pin.InceptionEvent = q.icp
		refuse(t, "a pinned inception that is not the history's", nil, p.bundle(), pin, p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a credential with a holder", func(t *testing.T) {
		p := onekey(t)
		p.foundRegistry()
		data := `{"dt":"2026-11-12T00:00:00Z","sequence":7,"published_at":"2026-11-12T00:00:00Z","expires_at":"2027-01-12T00:00:00Z","images":` + defaultImages(meas(7)) + `}`
		raw, err := keri.BuildCredential(keri.CredentialInput{SchemaSAID: p.schema, Issuer: p.aid, Registry: p.registry,
			Recipient: "DGLDzhg7VO1UEFOs4Av-gUU7hcRbdvyO_5nw7IbKBrQt", Data: []byte(data)})
		if err != nil {
			t.Fatal(err)
		}
		c, _ := keri.VerifyCredential(raw)
		iss, _ := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: c.SAID, Registry: p.registry, DT: "2026-11-12T00:00:00.000000+00:00"})
		ie, _ := keri.VerifyTELEvent(iss)
		p.creds, p.tel = append(p.creds, raw), append(p.tel, iss)
		p.seal(sealOf(c.SAID, 0, ie.SAID))
		refuse(t, "a list issued to somebody", ErrBadList, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a tampered credential", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		b := p.bundle()
		c := append([]byte{}, b.Credentials[0]...)
		c = []byte(strings.Replace(string(c), "EPYC-v4", "EPYC-v5", 1))
		b.Credentials = [][]byte{c}
		refuse(t, "a changed byte", ErrBadList, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
}

func TestFreshness(t *testing.T) {
	t.Run("a bundle older than the publisher's latest state", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		old := p.bundle()
		oldTip := p.tip()
		c8, _ := published(p, 8)
		p.revoke(c8) // the news a stale bundle would hide
		refuse(t, "stale bundle, fresh tip", ErrBehind, old, p.pin(), p.answers(p.tip(), 2), Floors{})
		_ = oldTip
	})
	t.Run("a bundle that goes past what the witnesses hold", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		behind := p.tip()
		published(p, 8)
		refuse(t, "witnesses behind the bundle", ErrAhead, p.bundle(), p.pin(), p.answers(behind, 2), Floors{})
	})
	t.Run("answers carrying another nonce", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		r := p.answers(p.tip(), 2)
		r[0].Nonce, r[1].Nonce = nonce(), nonce() // not the ones the answers were made for
		refuse(t, "replayed answers", ErrNotFresh, p.bundle(), p.pin(), r, Floors{})
	})
	t.Run("answers from fewer than the threshold", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		refuse(t, "one answer of two", ErrNotFresh, p.bundle(), p.pin(), p.answers(p.tip(), 1), Floors{})
		refuse(t, "no answers", ErrNotFresh, p.bundle(), p.pin(), nil, Floors{})
	})
	t.Run("answers from witnesses that are not the identity's", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		q := onekey(t)
		q.aid = p.aid
		refuse(t, "strangers answering", ErrNotFresh, p.bundle(), p.pin(), q.answers(p.tip(), 3), Floors{})
	})
	t.Run("witnesses that do not agree", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		other := Tip{SN: p.tip().SN, SAID: "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}
		r := []TipReply{p.answer(0, p.tip(), nonce()), p.answer(1, other, nonce())}
		refuse(t, "split tips", ErrWitnessesDisagree, p.bundle(), p.pin(), r, Floors{})
	})
	t.Run("a witness that signed two tips", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		other := Tip{SN: p.tip().SN, SAID: "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}
		r := []TipReply{p.answer(0, p.tip(), nonce()), p.answer(0, other, nonce()), p.answer(1, p.tip(), nonce())}
		refuse(t, "one witness, two answers", ErrWitnessesDisagree, p.bundle(), p.pin(), r, Floors{})
	})
	t.Run("a history that forks from the one held", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		held := tipAt(p, 1)
		f := Floors{HasKeyHistory: true, KeyHistorySN: held.SN, KeyHistorySAID: "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}
		err := refuse(t, "duplicity", ErrDuplicity, p.bundle(), p.pin(), p.answers(p.tip(), 2), f)
		var d *Duplicity
		if !errors.As(err, &d) || d.SN != held.SN || len(d.Message) == 0 {
			t.Fatalf("no evidence: %v", err)
		}
	})
	t.Run("a history shorter than the one held", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		f := Floors{HasKeyHistory: true, KeyHistorySN: int(p.last.SN) + 3, KeyHistorySAID: "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}
		refuse(t, "behind the floor", ErrBehind, p.bundle(), p.pin(), p.answers(p.tip(), 2), f)
	})
	t.Run("a floor that is not a place is refused and not indexed", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		for _, f := range []Floors{{HasKeyHistory: true, KeyHistorySN: -1, KeyHistorySAID: "E"}, {HasKeyHistory: true, KeyHistorySN: 1}} {
			refuse(t, "a bad floor", ErrMalformed, p.bundle(), p.pin(), p.answers(p.tip(), 2), f)
		}
	})
	t.Run("a history that extends the one held", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		held := tipAt(p, 2)
		published(p, 8)
		accept(t, p, Floors{HasKeyHistory: true, KeyHistorySN: held.SN, KeyHistorySAID: held.SAID})
	})
}

// #463's rules still hold on a list that is anchored.
func TestTheRulesOfASignedListStillHold(t *testing.T) {
	p := onekey(t)
	cred, _ := published(p, 7)
	t.Run("an older sequence than the floor", func(t *testing.T) {
		_, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{ListSequence: 9}, now)
		if !errors.Is(err, measurementlist.ErrOldList) {
			t.Fatal(err)
		}
	})
	t.Run("the floor's sequence with other content", func(t *testing.T) {
		_, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{ListSequence: 7, ListDigest: "EBBBB"}, now)
		if !errors.Is(err, measurementlist.ErrConflictingList) {
			t.Fatal(err)
		}
	})
	t.Run("the same list again", func(t *testing.T) {
		if _, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{ListSequence: 7, ListDigest: cred}, now); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		_, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{}, t0.Add(90*24*time.Hour))
		if !errors.Is(err, measurementlist.ErrExpired) {
			t.Fatal(err)
		}
	})
	t.Run("dated in the future", func(t *testing.T) {
		_, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{}, t0.Add(-time.Hour))
		if !errors.Is(err, measurementlist.ErrNotYetPublished) {
			t.Fatal(err)
		}
	})
	t.Run("an entry outside its window is carried and not accepted", func(t *testing.T) {
		q := onekey(t)
		q.foundRegistry()
		img := strings.Replace(defaultImages(meas(5)), `"valid_from":"2026-11-01T00:00:00Z"`, `"valid_from":"2027-01-01T00:00:00Z"`, 1)
		q.issue(listSpec{sequence: 5, expires: t0.Add(1000 * time.Hour), images: img})
		res := accept(t, q, Floors{})
		if len(res.List.Measurements("individual")) != 0 {
			t.Fatal("an entry not yet valid was accepted")
		}
	})
	t.Run("a malformed entry refuses the whole list", func(t *testing.T) {
		q := onekey(t)
		q.foundRegistry()
		img := strings.Replace(defaultImages(meas(5)), `"vcpus":1`, `"vcpus":0`, 1)
		q.issue(listSpec{sequence: 5, expires: t0.Add(1000 * time.Hour), images: img})
		refuse(t, "a bad entry", measurementlist.ErrBadEntry, q.bundle(), q.pin(), q.answers(q.tip(), 2), Floors{})
	})
}

func TestABundleThatIsNotWellFormed(t *testing.T) {
	for name, in := range map[string]string{
		"empty":           ``,
		"not json":        `not json`,
		"another version": `{"bundle_version":2,"publisher":"a","registry":"b","kel":[],"tel":[],"credentials":[]}`,
		"unknown field":   `{"bundle_version":1,"publisher":"a","registry":"b","kel":[],"tel":[],"credentials":[],"extra":1}`,
		"repeated key":    `{"bundle_version":1,"bundle_version":1,"publisher":"a","registry":"b","kel":[],"tel":[],"credentials":[]}`,
		"padded base64":   `{"bundle_version":1,"publisher":"a","registry":"b","kel":["AA=="],"tel":[],"credentials":[]}`,
	} {
		if _, err := ParseBundle([]byte(in)); err == nil {
			t.Errorf("%s: read as a bundle", name)
		}
	}
	if _, err := ParseBundle(make([]byte, MaxBundleBytes+1)); err == nil {
		t.Error("a bundle over the bound was read")
	}
}

func TestNoPinRefusesEverything(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	refuse(t, "no pin", ErrNoPin, p.bundle(), Pin{}, p.answers(p.tip(), 2), Floors{})
	if _, err := ParsePin("", "", "", ""); !errors.Is(err, ErrNoPin) {
		t.Fatal(err)
	}
}
