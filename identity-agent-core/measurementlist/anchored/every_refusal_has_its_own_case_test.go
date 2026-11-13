package anchored

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"
	"identity-agent-core/witness"
)

// One negative case for each refusal that would otherwise be hidden by another
// check: each bundle below is right in every other respect, so the case fails
// only if its own check is gone.

func listData(seq int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"dt":"%s","sequence":%d,"published_at":"%s","expires_at":"%s","images":%s}`,
		t0.Format(time.RFC3339), seq, t0.Format(time.RFC3339), t0.Add(60*24*time.Hour).Format(time.RFC3339), defaultImages(meas(byte(seq)))))
}

// issueAs issues the credential in, into the publisher's registry and seals it.
func (p *publisher) issueAs(in keri.CredentialInput) {
	p.t.Helper()
	raw, err := keri.BuildCredential(in)
	if err != nil {
		p.t.Fatal(err)
	}
	c, err := keri.VerifyCredential(raw)
	if err != nil {
		p.t.Fatal(err)
	}
	iss, err := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: c.SAID, Registry: p.registry, DT: "2026-11-12T00:00:00.000000+00:00"})
	if err != nil {
		p.t.Fatal(err)
	}
	ie, _ := keri.VerifyTELEvent(iss)
	p.creds, p.tel = append(p.creds, raw), append(p.tel, iss)
	p.issued[c.SAID] = iss
	p.seal(sealOf(c.SAID, 0, ie.SAID))
}

func (p *publisher) credentialInput() keri.CredentialInput {
	return keri.CredentialInput{SchemaSAID: p.schema, Issuer: p.aid, Registry: p.registry, Data: listData(7)}
}

func TestTheRegistryInceptionIsHeldToEveryPin(t *testing.T) {
	// A registry inception seals itself ({i, s: 0, d} with i equal to d), and a
	// seal of that shape is read only for the pinned registry (readLog); so an
	// inception that is not the pinned one is refused as one the history never
	// sealed, before the check of its own identifier can be reached.
	t.Run("an inception whose identifier is not the pinned registry", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		pin := p.pin()
		pin.Registry = "E" + strings.Repeat("R", 43)
		b := p.bundle()
		b.Registry = pin.Registry
		refuse(t, "another registry's inception", ErrUnsealed, b, pin, p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a registry of another issuer, sealed by the publisher", func(t *testing.T) {
		p, q := onekey(t), onekey(t)
		vcp, err := keri.BuildRegistryInception(keri.RegistryInput{Issuer: q.aid, Nonce: "0AB2dnZ2dnZ2dnZ2dnZ2dnZ2", NoBackers: true})
		if err != nil {
			t.Fatal(err)
		}
		ev, _ := keri.VerifyTELEvent(vcp)
		p.registry, p.tel = ev.SAID, append(p.tel, vcp)
		p.seal(sealOf(ev.SAID, 0, ev.SAID))
		p.issueAs(p.credentialInput())
		refuse(t, "a registry that another identity governs", ErrBadRegistry, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("two registry inceptions", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		vcp, _ := keri.BuildRegistryInception(keri.RegistryInput{Issuer: p.aid, Nonce: "0ACdnZ2dnZ2dnZ2dnZ2dnZ2d", NoBackers: true})
		ev, _ := keri.VerifyTELEvent(vcp)
		p.tel = append(p.tel, vcp)
		p.seal(sealOf(ev.SAID, 0, ev.SAID))
		refuse(t, "a second registry", ErrUnsealed, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
}

func TestTheCredentialIsHeldToEveryField(t *testing.T) {
	cases := map[string]func(p, q *publisher, in *keri.CredentialInput){
		"issued by another identity": func(p, q *publisher, in *keri.CredentialInput) { in.Issuer = q.aid },
		"naming another registry":    func(p, q *publisher, in *keri.CredentialInput) { in.Registry = "E" + strings.Repeat("R", 43) },
		"a private credential with a salt": func(p, q *publisher, in *keri.CredentialInput) {
			in.Private, in.Salt = true, "0AB2dnZ2dnZ2dnZ2dnZ2dnZ2"
		},
		"with edges": func(p, q *publisher, in *keri.CredentialInput) {
			in.Source = json.RawMessage(`{"d":"","other":{"n":"E` + strings.Repeat("S", 43) + `"}}`)
		},
		"with rules": func(p, q *publisher, in *keri.CredentialInput) {
			in.Rules = json.RawMessage(`{"d":"","usage":{"l":"for anybody"}}`)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, q := onekey(t), onekey(t)
			p.foundRegistry()
			in := p.credentialInput()
			mutate(p, q, &in)
			p.issueAs(in)
			refuse(t, name, ErrBadList, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
		})
	}
}

func TestTheOrderAndShapeOfWhatTheRegistryHolds(t *testing.T) {
	t.Run("an issuance sealed before the registry exists", func(t *testing.T) {
		p := onekey(t)
		vcp, _ := keri.BuildRegistryInception(keri.RegistryInput{Issuer: p.aid, Nonce: "0AB2dnZ2dnZ2dnZ2dnZ2dnZ2", NoBackers: true})
		ev, _ := keri.VerifyTELEvent(vcp)
		p.registry = ev.SAID
		p.issueAs(p.credentialInput()) // sealed first
		p.tel = append([][]byte{vcp}, p.tel...)
		p.seal(sealOf(ev.SAID, 0, ev.SAID)) // the registry is sealed after
		refuse(t, "issuance before registry", ErrBadTEL, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("an event of another registry", func(t *testing.T) {
		p := onekey(t)
		p.foundRegistry()
		raw, _ := keri.BuildCredential(p.credentialInput())
		c, _ := keri.VerifyCredential(raw)
		iss, _ := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: c.SAID, Registry: "E" + strings.Repeat("R", 43), DT: "2026-11-12T00:00:00.000000+00:00"})
		ie, _ := keri.VerifyTELEvent(iss)
		p.creds, p.tel = append(p.creds, raw), append(p.tel, iss)
		p.seal(sealOf(c.SAID, 0, ie.SAID))
		refuse(t, "an issuance into another registry", ErrBadTEL, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a withdrawal that names another issuance", func(t *testing.T) {
		p := onekey(t)
		c7, _ := published(p, 7)
		rev, err := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: c7, Registry: p.registry,
			PriorISSSAID: "E" + strings.Repeat("P", 43), DT: "2026-11-12T00:00:00.000000+00:00"})
		if err != nil {
			t.Fatal(err)
		}
		re, _ := keri.VerifyTELEvent(rev)
		p.tel = append(p.tel, rev)
		p.seal(sealOf(c7, 1, re.SAID))
		refuse(t, "a revocation of nothing", ErrBadTEL, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a withdrawal of a credential never issued", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		raw, _ := keri.BuildCredential(keri.CredentialInput{SchemaSAID: p.schema, Issuer: p.aid, Registry: p.registry, Data: listData(8)})
		c, _ := keri.VerifyCredential(raw)
		rev, _ := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: c.SAID, Registry: p.registry,
			PriorISSSAID: "E" + strings.Repeat("P", 43), DT: "2026-11-12T00:00:00.000000+00:00"})
		re, _ := keri.VerifyTELEvent(rev)
		p.tel = append(p.tel, rev)
		p.seal(sealOf(c.SAID, 1, re.SAID))
		refuse(t, "a withdrawal with no issuance", ErrBadTEL, p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("the same registry event twice", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		b := p.bundle()
		b.TEL = append(b.TEL, b.TEL[len(b.TEL)-1])
		refuse(t, "an event repeated", ErrBadTEL, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
}

func TestTheCredentialsOfABundle(t *testing.T) {
	t.Run("the same credential twice", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		b := p.bundle()
		b.Credentials = append(b.Credentials, b.Credentials[0])
		refuse(t, "a credential repeated", ErrBadList, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("a credential no issuance covers", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		raw, _ := keri.BuildCredential(keri.CredentialInput{SchemaSAID: p.schema, Issuer: p.aid, Registry: p.registry, Data: listData(8)})
		b := p.bundle()
		b.Credentials = append(b.Credentials, raw)
		refuse(t, "a credential never issued", ErrUnsealed, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("an issuance whose credential is not in the bundle", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		b := p.bundle()
		b.Credentials = nil
		refuse(t, "an issuance without its list", ErrWithheld, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
	t.Run("the newest list is the one sealed last, not the one that comes last in the bundle", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		published(p, 8)
		b := p.bundle()
		// the registry's events and the credentials in the order that would
		// favour the older list
		n := len(b.TEL)
		b.TEL = append([][]byte{b.TEL[0]}, reverse(b.TEL[1:n])...)
		b.Credentials = reverse(b.Credentials)
		res, err := Verify(b, p.pin(), p.answers(p.tip(), 2), Floors{}, now)
		if err != nil || res.List.Sequence != 8 {
			t.Fatalf("with the bundle's parts reordered the answer is %v (%v)", res, err)
		}
	})
	t.Run("a bundle with no key history", func(t *testing.T) {
		p := onekey(t)
		published(p, 7)
		b := p.bundle()
		b.KEL = nil
		refuse(t, "no history", ErrMalformed, b, p.pin(), p.answers(p.tip(), 2), Floors{})
	})
}

func reverse(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}

func TestAgreedTipHoldsEachConditionOnItsOwn(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	tip := p.tip()
	designated := pubs(p.witness...)
	good := func() []TipReply { return p.answers(tip, 2) }
	if _, err := AgreedTip(p.aid, designated, 2, good()); err != nil {
		t.Fatalf("control: %v", err)
	}
	t.Run("an answer about another identity", func(t *testing.T) {
		// validly signed by the designated witnesses, with the nonce asked, but for someone else
		var r []TipReply
		for i := 0; i < 2; i++ {
			n := nonce()
			st := witness.TipStatement("D"+strings.Repeat("X", 43), n, tip.SN, tip.SAID)
			sig, _ := p.witness[i].signer.Sign([]byte(st))
			q, _ := keri.MatterQB64("0B", sig)
			r = append(r, TipReply{Nonce: n, Answer: witness.TipAnswer{AID: "D" + strings.Repeat("X", 43), Nonce: n, SN: tip.SN, SAID: tip.SAID,
				WitnessAID: p.witness[i].pub, Signature: q}})
		}
		if _, err := AgreedTip(p.aid, designated, 2, r); !errorsIs(err, ErrNotFresh) {
			t.Fatalf("answers about another identity counted: %v", err)
		}
	})
	t.Run("a nonce shorter than the minimum", func(t *testing.T) {
		short := strings.Repeat("n", MinNonceLen-1)
		r := []TipReply{p.answer(0, tip, short), p.answer(1, tip, short)}
		if _, err := AgreedTip(p.aid, designated, 2, r); !errorsIs(err, ErrNotFresh) {
			t.Fatalf("a short nonce counted: %v", err)
		}
		long := strings.Repeat("n", MinNonceLen)
		r = []TipReply{p.answer(0, tip, long), p.answer(1, tip, long)}
		if _, err := AgreedTip(p.aid, designated, 2, r); err != nil {
			t.Fatalf("a nonce of the minimum length was refused: %v", err)
		}
	})
	t.Run("a threshold of nothing", func(t *testing.T) {
		for _, th := range []int{0, -1} {
			if _, err := AgreedTip(p.aid, designated, th, good()); !errorsIs(err, ErrNotFresh) {
				t.Fatalf("threshold %d: %v", th, err)
			}
		}
		if _, err := AgreedTip(p.aid, nil, 2, good()); !errorsIs(err, ErrNotFresh) {
			t.Fatalf("no witnesses to ask: %v", err)
		}
	})
	t.Run("the witnesses hold nothing", func(t *testing.T) {
		none := Tip{SN: -1}
		if _, err := AgreedTip(p.aid, designated, 2, p.answers(none, 2)); !errorsIs(err, ErrNotFresh) {
			t.Fatalf("an empty answer was a tip: %v", err)
		}
	})
	t.Run("an answer that is both a tip and not", func(t *testing.T) {
		both := Tip{SN: 3, SAID: ""} // a place but no event
		if _, err := AgreedTip(p.aid, designated, 2, p.answers(both, 2)); !errorsIs(err, ErrNotFresh) {
			t.Fatalf("a place with no event counted: %v", err)
		}
		other := Tip{SN: -1, SAID: tip.SAID} // an event but no place
		if _, err := AgreedTip(p.aid, designated, 2, p.answers(other, 2)); !errorsIs(err, ErrNotFresh) {
			t.Fatalf("an event with no place counted: %v", err)
		}
	})
	t.Run("a witness counted twice", func(t *testing.T) {
		r := []TipReply{p.answer(0, tip, nonce()), p.answer(0, tip, nonce())}
		if _, err := AgreedTip(p.aid, designated, 2, r); !errorsIs(err, ErrNotFresh) {
			t.Fatalf("one witness answering twice met a threshold of two: %v", err)
		}
	})
	t.Run("a witness that is not designated", func(t *testing.T) {
		r := []TipReply{p.answer(0, tip, nonce()), p.answer(1, tip, nonce())}
		if _, err := AgreedTip(p.aid, designated[1:], 2, r); !errorsIs(err, ErrNotFresh) {
			t.Fatalf("an undesignated witness counted: %v", err)
		}
	})
}
