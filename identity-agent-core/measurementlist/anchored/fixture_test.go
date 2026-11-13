package anchored

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/witness"
)

// These tests build a publisher the way the real one is built, from keri-go's
// own builders: an identity with members at a threshold, witnesses that receipt
// every event, a backerless registry, and lists issued and withdrawn into it.
// Nothing here is a checker's own idea of what a publisher is.

const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

var t0 = time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)

type member struct {
	signer keri.Signer
	pub    string
	digest string
}

func newMember(t testing.TB, transferable bool) member {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := keri.NewSoftwareSigner(seed, transferable)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := keri.NextDigest(pub)
	if err != nil {
		t.Fatal(err)
	}
	return member{s, pub, d}
}

func pubs(ms ...member) []string {
	var o []string
	for _, m := range ms {
		o = append(o, m.pub)
	}
	return o
}
func digests(ms ...member) []string {
	var o []string
	for _, m := range ms {
		o = append(o, m.digest)
	}
	return o
}

// publisher is a publisher identity as a test holds it.
type publisher struct {
	t        testing.TB
	aid      string
	witness  []member
	toad     int
	msgs     [][]byte // the history, each with its signatures and receipts
	last     *keri.Event
	registry string
	tel      [][]byte
	creds    [][]byte
	issued   map[string][]byte // credential SAID to its iss event
	schema   string
	icp      []byte
	cur      []member // keys in force
	// fault injection: how many controller signers sign (0: all), how many
	// receipts an event gets (-1: the threshold), and who receipts instead
	signWith int
	receipts int
	rogue    []member
	// wrongSeal makes the next issuance's seal name another digest
	wrongSeal bool
	next      []member // keys committed to
	kt, nt    string
}

type found struct {
	keys, next []member
	kt, nt     string
	witnesses  int
	toad       int
}

func newPublisher(t testing.TB, f found) *publisher {
	t.Helper()
	p := &publisher{t: t, receipts: -1, schema: "ECK0xZlkjmPoOv0NGGFy2-_j_e9zc0yxayHH0pNeox8w", issued: map[string][]byte{},
		cur: f.keys, next: f.next, kt: f.kt, nt: f.nt, toad: f.toad}
	for i := 0; i < f.witnesses; i++ {
		p.witness = append(p.witness, newMember(t, false))
	}
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys: pubs(f.keys...), Isith: json.RawMessage(f.kt), NextDigests: digests(f.next...), Nsith: json.RawMessage(f.nt),
		Witnesses: pubs(p.witness...), Toad: &f.toad,
	})
	if err != nil {
		t.Fatal(err)
	}
	p.icp = raw
	ev, _ := keri.ParseEvent(raw)
	p.aid, p.last = ev.Identifier, ev
	p.msgs = append(p.msgs, p.frame(raw, p.sign(raw, f.keys, nil), p.toad))
	return p
}

type place struct{ index, ondex int }

// sign signs event with signers at their places (the same place when nil).
func (p *publisher) sign(event []byte, ms []member, places []place) []keri.PlacedSigner {
	var out []keri.PlacedSigner
	for i, m := range ms {
		at := keri.SamePlace(i)
		if places != nil {
			at = keri.SignaturePlace{Index: places[i].index, Ondex: places[i].ondex}
		}
		out = append(out, keri.PlacedSigner{Signer: m.signer, At: at})
	}
	return out
}

// frame attaches controller signatures and the first n witnesses' receipts.
func (p *publisher) frame(event []byte, signers []keri.PlacedSigner, receipts int) []byte {
	p.t.Helper()
	if p.receipts >= 0 {
		receipts = p.receipts
	}
	if p.signWith > 0 && p.signWith < len(signers) {
		signers = signers[:p.signWith]
	}
	wit := p.witness
	if p.rogue != nil {
		wit = p.rogue
	}
	se, err := keri.SignEventAt(event, signers...)
	if err != nil {
		p.t.Fatal(err)
	}
	msg := append([]byte{}, se.Message...)
	if receipts > 0 {
		msg = append(msg, '-', 'B', b64[receipts/64], b64[receipts%64])
		for i := 0; i < receipts; i++ {
			raw, err := wit[i].signer.Sign(event)
			if err != nil {
				p.t.Fatal(err)
			}
			q, err := keri.EncodeIndexedSignature(raw, keri.SamePlace(i))
			if err != nil {
				p.t.Fatal(err)
			}
			msg = append(msg, q...)
		}
	}
	return msg
}

func (p *publisher) add(raw []byte, signed []keri.PlacedSigner, receipts int) {
	p.t.Helper()
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		p.t.Fatal(err)
	}
	p.msgs = append(p.msgs, p.frame(raw, signed, receipts))
	p.last = ev
}

// seal makes an interaction event sealing the given anchors, signed by the
// members in force, receipted by the threshold of witnesses.
func (p *publisher) seal(seals ...json.RawMessage) int {
	p.t.Helper()
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: p.aid, PriorSAID: p.last.SAID, SN: int(p.last.SN) + 1, Data: seals})
	if err != nil {
		p.t.Fatal(err)
	}
	p.add(raw, p.sign(raw, p.cur, nil), p.toad)
	return int(p.last.SN)
}

func sealOf(i string, sn int, d string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"i":"%s","s":"%x","d":"%s"}`, i, sn, d))
}

// found the registry, sealed.
func (p *publisher) foundRegistry() {
	p.t.Helper()
	vcp, err := keri.BuildRegistryInception(keri.RegistryInput{Issuer: p.aid, Nonce: "0AB2dnZ2dnZ2dnZ2dnZ2dnZ2", NoBackers: true})
	if err != nil {
		p.t.Fatal(err)
	}
	ev, _ := keri.VerifyTELEvent(vcp)
	p.registry = ev.SAID
	p.tel = append(p.tel, vcp)
	p.seal(sealOf(ev.SAID, 0, ev.SAID))
}

type listSpec struct {
	sequence int
	expires  time.Time
	images   string // the images object, as JSON
	extra    string // attribute fields to add before "sequence", as JSON members ending in a comma
}

func defaultImages(measurementHex string) string {
	return fmt.Sprintf(`{"individual":[{"image":"individual-v1","measurement":"%s","computed_from":{"ovmf_sha256":"%064x","vcpus":1,"cpu_model":"EPYC-v4","cmdline_sha256":"%064x"},"valid_from":"2026-11-01T00:00:00Z","valid_until":null}]}`,
		measurementHex, 1, 2)
}

func meas(b byte) string { return fmt.Sprintf("%096x", int(b)) }

// issue makes the credential for spec, its issuance and the seal of it.
func (p *publisher) issue(s listSpec) (credSAID string, issSealPos int) {
	p.t.Helper()
	data := fmt.Sprintf(`{"dt":"%s",%s"sequence":%d,"published_at":"%s","expires_at":"%s","images":%s}`,
		t0.Format(time.RFC3339), s.extra, s.sequence, t0.Format(time.RFC3339), s.expires.Format(time.RFC3339), s.images)
	raw, err := keri.BuildCredential(keri.CredentialInput{SchemaSAID: p.schema, Issuer: p.aid, Registry: p.registry, Data: json.RawMessage(data)})
	if err != nil {
		p.t.Fatal(err)
	}
	cred, err := keri.VerifyCredential(raw)
	if err != nil {
		p.t.Fatal(err)
	}
	iss, err := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: cred.SAID, Registry: p.registry, DT: t0.Format("2006-01-02T15:04:05.000000+00:00")})
	if err != nil {
		p.t.Fatal(err)
	}
	ie, _ := keri.VerifyTELEvent(iss)
	p.creds = append(p.creds, raw)
	p.tel = append(p.tel, iss)
	p.issued[cred.SAID] = iss
	d := ie.SAID
	if p.wrongSeal {
		d = p.registry
	}
	return cred.SAID, p.seal(sealOf(cred.SAID, 0, d))
}

// revoke withdraws a list and seals it. It returns the revocation event.
func (p *publisher) revoke(credSAID string) []byte {
	p.t.Helper()
	ie, _ := keri.VerifyTELEvent(p.issued[credSAID])
	rev, err := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: credSAID, Registry: p.registry, PriorISSSAID: ie.SAID,
		DT: t0.Format("2006-01-02T15:04:05.000000+00:00")})
	if err != nil {
		p.t.Fatal(err)
	}
	re, _ := keri.VerifyTELEvent(rev)
	p.tel = append(p.tel, rev)
	p.seal(sealOf(credSAID, 1, re.SAID))
	return rev
}

func (p *publisher) pin() Pin {
	return Pin{Publisher: p.aid, InceptionEvent: p.icp, Registry: p.registry, SchemaSAID: p.schema}
}

func (p *publisher) bundle() *Bundle {
	return &Bundle{Version: BundleVersion, Publisher: p.aid, Registry: p.registry,
		KEL: append([][]byte{}, p.msgs...), TEL: append([][]byte{}, p.tel...), Credentials: append([][]byte{}, p.creds...)}
}

func (p *publisher) tip() Tip { return Tip{SN: int(p.last.SN), SAID: p.last.SAID} }

// answers is what the first n witnesses say the tip is, to a nonce each was sent.
func (p *publisher) answers(tip Tip, n int) []TipReply {
	var out []TipReply
	for i := 0; i < n && i < len(p.witness); i++ {
		out = append(out, p.answer(i, tip, nonce()))
	}
	return out
}

func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (p *publisher) answer(i int, tip Tip, n string) TipReply {
	st := witness.TipStatement(p.aid, n, tip.SN, tip.SAID)
	raw, err := p.witness[i].signer.Sign([]byte(st))
	if err != nil {
		p.t.Fatal(err)
	}
	q, err := keri.MatterQB64("0B", raw)
	if err != nil {
		p.t.Fatal(err)
	}
	return TipReply{Nonce: n, Answer: witness.TipAnswer{AID: p.aid, Nonce: n, SN: tip.SN, SAID: tip.SAID, WitnessAID: p.witness[i].pub, Signature: q}}
}

// onekey is the plan A publisher: one member key, a threshold of one.
func onekey(t testing.TB) *publisher {
	k, n := newMember(t, true), newMember(t, true)
	return newPublisher(t, found{keys: []member{k}, next: []member{n}, kt: `"1"`, nt: `"1"`, witnesses: 3, toad: 2})
}

// rotate makes a rotation to keys (committing to next), signed by signers at
// their places, and moves the keys in force.
func (p *publisher) rotate(keys, next []member, kt, nt string, signers []member, places []place) {
	p.t.Helper()
	to := p.toad
	raw, err := keri.BuildRotation(keri.RotationInput{Prefix: p.aid, Keys: pubs(keys...), PriorSAID: p.last.SAID, SN: int(p.last.SN) + 1,
		NextDigests: digests(next...), Isith: json.RawMessage(kt), Nsith: json.RawMessage(nt),
		PriorWitnesses: pubs(p.witness...), Toad: &to})
	if err != nil {
		p.t.Fatal(err)
	}
	p.add(raw, p.sign(raw, signers, places), p.toad)
	p.cur, p.next, p.kt, p.nt = keys, next, kt, nt
}

// tipAt is the place of the n-th message of the history.
func tipAt(p *publisher, n int) Tip {
	raw, err := keri.EventOfMessage(p.msgs[n])
	if err != nil {
		p.t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		p.t.Fatal(err)
	}
	return Tip{SN: int(ev.SN), SAID: ev.SAID}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func base64RawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
