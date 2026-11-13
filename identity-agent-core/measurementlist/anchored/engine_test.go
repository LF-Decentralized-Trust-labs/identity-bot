package anchored

import (
	"encoding/base64"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
)

// The whole way: the real engine founds a witnessed identity, founds a
// backerless registry, issues lists to nobody, withdraws one, and the checker
// accepts what comes out. Nothing here is built by hand but the witnesses'
// receipts, which a real witness adds and this test's witnesses add the same
// way.
func TestAListMadeByTheEngineIsCheckedByTheChecker(t *testing.T) {
	eng := keriengine.New()
	key, next := newMember(t, true), newMember(t, true)
	eng.SetEventSignature(func(aid, k string, raw []byte) (string, error) {
		if k != key.pub {
			t.Fatalf("asked to sign under %s", k)
		}
		sig, err := key.signer.Sign(raw)
		if err != nil {
			return "", err
		}
		return keri.MatterQB64(keri.CodeEd25519Sig, sig)
	})
	wit := []member{newMember(t, false), newMember(t, false), newMember(t, false)}
	inc, err := eng.Incept(drivers.InceptionRequest{PublicKey: key.pub, NextPublicKey: next.pub, Name: "publisher",
		Witnesses: pubs(wit...), Toad: 2})
	if err != nil {
		t.Fatalf("founding: %v", err)
	}
	reg, err := eng.InceptBackerlessRegistry("publisher")
	if err != nil {
		t.Fatalf("the registry: %v", err)
	}
	schema := "ECK0xZlkjmPoOv0NGGFy2-_j_e9zc0yxayHH0pNeox8w"
	var tel, creds [][]byte
	vcp, _ := base64.StdEncoding.DecodeString(reg.VcpJsonB64)
	tel = append(tel, vcp)
	issue := func(seq int) string {
		claims := map[string]interface{}{"sequence": seq, "published_at": t0.Format("2006-01-02T15:04:05Z"),
			"expires_at": t0.Add(1440 * 3600 * 1e9).Format("2006-01-02T15:04:05Z")}
		var images map[string]interface{}
		_ = jsonUnmarshal([]byte(defaultImages(meas(byte(seq)))), &images)
		claims["images"] = images
		r, err := eng.IssueUntargetedCredentialInRegistry("publisher", claims, schema, reg.RegistrySaid)
		if err != nil {
			t.Fatalf("issuing list %d: %v", seq, err)
		}
		acdc, _ := base64.StdEncoding.DecodeString(r.AcdcJsonB64)
		iss, _ := base64.StdEncoding.DecodeString(r.IssRawBytesB64)
		creds, tel = append(creds, acdc), append(tel, iss)
		return r.AcdcSaid
	}
	c7 := issue(7)
	c8 := issue(8)
	revoked, err := eng.RevokeCredential("publisher", c8, reg.RegistrySaid, "")
	if err != nil {
		t.Fatalf("withdrawing list 8: %v", err)
	}
	rev, _ := base64.StdEncoding.DecodeString(revoked.RevRawBytesB64)
	tel = append(tel, rev)

	// the history as the witnesses would serve it
	kel, err := eng.GetKelByAID(inc.AID)
	if err != nil {
		t.Fatal(err)
	}
	var msgs [][]byte
	for i, rb := range kel.RawEventsB64 {
		raw, _ := base64.StdEncoding.DecodeString(rb)
		m, err := drivers.SignedMessage(raw, kel.Signatures[i])
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		m = append(m, '-', 'B', b64[2/64], b64[2%64])
		for w := 0; w < 2; w++ {
			s, _ := wit[w].signer.Sign(raw)
			q, _ := keri.EncodeIndexedSignature(s, keri.SamePlace(w))
			m = append(m, q...)
		}
		msgs = append(msgs, m)
	}
	stream, err := keri.ExportKEL(msgs)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle(inc.AID, reg.RegistrySaid, stream, tel, creds)
	if err != nil {
		t.Fatal(err)
	}
	icp, _ := keri.EventOfMessage(msgs[0])
	pin := Pin{Publisher: inc.AID, InceptionEvent: icp, Registry: reg.RegistrySaid, SchemaSAID: schema}
	last := msgs[len(msgs)-1]
	le, _ := keri.EventOfMessage(last)
	lev, _ := keri.ParseEvent(le)
	tip := Tip{SN: int(lev.SN), SAID: lev.SAID}
	p := &publisher{t: t, aid: inc.AID, witness: wit}
	res, err := Verify(b, pin, p.answers(tip, 2), Floors{}, now)
	if err != nil {
		t.Fatalf("what the engine made was refused: %v", err)
	}
	if res.CredentialSAID != c7 || res.List.Sequence != 7 {
		t.Fatalf("with list 8 withdrawn the answer is list %d (%s)", res.List.Sequence, res.CredentialSAID)
	}
	// withhold the withdrawal and list 8 would be taken as current: refused
	b.TEL = b.TEL[:len(b.TEL)-1]
	refuse(t, "the engine's withdrawal withheld", ErrWithheld, b, pin, p.answers(tip, 2), Floors{})
}
