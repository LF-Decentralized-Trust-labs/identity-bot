package agentpeer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/didcomm"
	"identity-agent-core/fingerprint"
)

var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

type pair struct {
	alpha, beta       *didcomm.KeySet
	alphaDID, betaDID *didcomm.DID
}

func newPair(t *testing.T) pair {
	t.Helper()
	g, err := didcomm.GenerateKeySet("EALPHA")
	if err != nil {
		t.Fatal(err)
	}
	v, err := didcomm.GenerateKeySet("EBETA")
	if err != nil {
		t.Fatal(err)
	}
	gd, _ := g.DID()
	vd, _ := v.DID()
	return pair{g, v, gd, vd}
}

func ask() Statement {
	return Statement{Kind: KindAsk, ToAID: "EBETA", FromAgent: "EALPHAAGENT", ToAgent: "EBETAAGENT", MessageID: "m-1"}
}

// A message Alpha's Identity Agent seals is taken by Beta's, with the
// words it covers, as from Alpha and for Beta.
func TestASealedMessageIsTakenByTheIdentityAgentItIsFor(t *testing.T) {
	p := newPair(t)
	m, err := Seal(p.alpha, ask(), "Please review this change.", now)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Verify(m, p.alphaDID, "EALPHA", "EBETA", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("a good message was refused: %v", err)
	}
	if s.FromAID != "EALPHA" || s.ToAgent != "EBETAAGENT" || s.Kind != KindAsk || s.Fingerprint == "" {
		t.Fatalf("read as %+v", s)
	}
}

// The message is a KERI exchange message in keri-go's one form (the form a
// keripy Exchanger accepts: exchange_test.go in keri-go holds that), and it
// holds neither the words nor the salt.
func TestTheSignedMessageIsAnExchangeMessageThatHoldsNoWords(t *testing.T) {
	p := newPair(t)
	m, err := Seal(p.alpha, ask(), "a secret ask", now)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := keri.VerifyExchangeSigned([]byte(m.Exn))
	if err != nil {
		t.Fatal(err)
	}
	if ex.Route != "/ia/agent/peer/ask" || ex.Recipient != "EBETA" || ex.Prior != "" {
		t.Fatalf("route %q recipient %q prior %q", ex.Route, ex.Recipient, ex.Prior)
	}
	if strings.Contains(m.Exn, "a secret ask") || strings.Contains(m.Exn, m.Salt) {
		t.Fatal("the signed message carries the words or the salt")
	}
	want, _ := SenderIdentifier(p.alpha.EdPub)
	if ex.Sender != want {
		t.Fatalf("sent as %s, want the sending Identity Agent's messaging key %s", ex.Sender, want)
	}
}

// Each message is under a salt of its own, so the same words twice give two
// fingerprints and a short answer cannot be confirmed by hashing guesses.
func TestTheSameWordsTwiceHaveTwoFingerprints(t *testing.T) {
	p := newPair(t)
	a, _ := Seal(p.alpha, ask(), "yes", now)
	b, _ := Seal(p.alpha, ask(), "yes", now)
	sa, _ := ReadStatement(a.Signed, p.alphaDID)
	sb, _ := ReadStatement(b.Signed, p.alphaDID)
	if sa.Fingerprint == sb.Fingerprint || a.Salt == b.Salt {
		t.Fatal("two messages of the same words share a fingerprint or a salt")
	}
	salt, _ := base64.RawURLEncoding.DecodeString(a.Salt)
	if f, _ := fingerprint.Of(salt, []byte("yes")); f != sa.Fingerprint {
		t.Fatal("the fingerprint is not ADR-067's")
	}
}

// signedFrom signs an exchange message the way Seal does, from parts a test
// edits, so only the rule under test can refuse it.
type parts struct {
	st        Statement
	prior     string
	modifiers json.RawMessage
	data      string          // `a` after the recipient, when not the statement's
	recipient string          // when not the statement's
	sender    string          // when not the keyset's
	route     string          // when not the statement kind's
	edBy      *didcomm.KeySet // whose Ed25519 key signs, when not the keyset's
}

func (p parts) sealWith(t *testing.T, k *didcomm.KeySet, words, salt string) Message {
	t.Helper()
	data, err := p.st.attributes()
	if err != nil {
		t.Fatal(err)
	}
	if p.data != "" {
		data = json.RawMessage(p.data)
	}
	rcpt, route, sender := p.st.ToAID, Route(p.st.Kind), ""
	sender, _ = SenderIdentifier(k.EdPub)
	if p.recipient != "" {
		rcpt = p.recipient
	}
	if p.route != "" {
		route = p.route
	}
	if p.sender != "" {
		sender = p.sender
	}
	raw, err := keri.BuildExchange(keri.ExchangeInput{Sender: sender, Recipient: rcpt, Prior: p.prior,
		DT: p.st.SentAt, Route: route, Modifiers: p.modifiers, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	edKey := k.EdPriv
	if p.edBy != nil {
		edKey = p.edBy.EdPriv
	}
	stream, err := keri.SignExchange(raw, edKey)
	if err != nil {
		t.Fatal(err)
	}
	return Message{Signed: Signed{Exn: string(stream),
		PQSig: base64.RawURLEncoding.EncodeToString(k.SignPostQuantum(pqInput(raw)))},
		Words: words, Salt: salt}
}

// goodParts is a statement for words under a salt, as Seal would make it.
func goodParts(t *testing.T, from, words string) (parts, string) {
	t.Helper()
	salt, _ := fingerprint.NewSalt()
	st := ask()
	st.FromAID = from
	st.Fingerprint, _ = fingerprint.Of(salt, []byte(words))
	st.SentAt = now.Format(sentAtLayout)
	return parts{st: st}, base64.RawURLEncoding.EncodeToString(salt)
}

// One test per rule: each refusal below is what a different check does, so
// removing any one check fails exactly its own case.
func TestEachRuleRefusesItsOwnMessage(t *testing.T) {
	p := newPair(t)
	other, _ := didcomm.GenerateKeySet("EALPHA")
	otherDID, _ := other.DID()
	sealed := func(edit func(*parts)) Message {
		pt, salt := goodParts(t, "EALPHA", "words")
		if edit != nil {
			edit(&pt)
		}
		return pt.sealWith(t, p.alpha, "words", salt)
	}
	good, _ := Seal(p.alpha, ask(), "x", now)
	bad := func(m Message, f func(*Message)) Message { f(&m); return m }

	cases := []struct {
		name   string
		msg    Message
		signer *didcomm.DID
		by     string
		self   string
		at     time.Time
		want   *Refusal
	}{
		{"no message", Message{Words: "x"}, p.alphaDID, "EALPHA", "EBETA", now, ErrNoEntry},
		{"not an exchange message", bad(good, func(m *Message) { m.Exn = "{}" }), p.alphaDID, "EALPHA", "EBETA", now, ErrUnreadable},
		{"signed by other messaging keys than the sender's", good, otherDID, "EALPHA", "EBETA", now, ErrNotSigned},
		{"sent as another key than the sender's", sealed(func(pt *parts) { pt.sender, _ = SenderIdentifier(other.EdPub); pt.edBy = other }), p.alphaDID, "EALPHA", "EBETA", now, ErrNotSigned},
		{"no post-quantum signature", bad(good, func(m *Message) { m.PQSig = "" }), p.alphaDID, "EALPHA", "EBETA", now, ErrNotSigned},
		{"a post-quantum signature over something else", bad(good, func(m *Message) {
			m.PQSig = base64.RawURLEncoding.EncodeToString(p.alpha.SignPostQuantum([]byte("something else")))
		}), p.alphaDID, "EALPHA", "EBETA", now, ErrNotSigned},
		{"the envelope came from another Identity Agent", good, p.alphaDID, "EMALLORY", "EBETA", now, ErrWrongSender},
		{"for another Identity Agent", good, p.alphaDID, "EALPHA", "ESOMEONEELSE", now, ErrWrongRecipient},
		{"words changed after signing", bad(sealed(nil), func(m *Message) { m.Words = "changed" }), p.alphaDID, "EALPHA", "EBETA", now, ErrFingerprint},
		{"the salt of another message", bad(good, func(m *Message) { m.Salt = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")) }), p.alphaDID, "EALPHA", "EBETA", now, ErrFingerprint},
		{"no words", bad(good, func(m *Message) { m.Words = "" }), p.alphaDID, "EALPHA", "EBETA", now, ErrWords},
		{"no salt", bad(good, func(m *Message) { m.Salt = "" }), p.alphaDID, "EALPHA", "EBETA", now, ErrSalt},
		{"a salt too short", bad(good, func(m *Message) { m.Salt = base64.RawURLEncoding.EncodeToString([]byte("short")) }), p.alphaDID, "EALPHA", "EBETA", now, ErrSalt},
		{"dated long ago", good, p.alphaDID, "EALPHA", "EBETA", now.Add(2 * time.Hour), ErrTime},
		{"dated in the future", good, p.alphaDID, "EALPHA", "EBETA", now.Add(-2 * time.Hour), ErrTime},
		{"a reply that answers nothing", sealed(func(pt *parts) { pt.st.Kind = KindReply }), p.alphaDID, "EALPHA", "EBETA", now, ErrReplyTo},
		{"an ask that answers something", sealed(func(pt *parts) { pt.st.InReplyTo = "m-0" }), p.alphaDID, "EALPHA", "EBETA", now, ErrReplyTo},
		{"an unknown kind", sealed(func(pt *parts) { pt.route = "/ia/agent/peer/order" }), p.alphaDID, "EALPHA", "EBETA", now, ErrKind},
		{"another route", sealed(func(pt *parts) { pt.route = "/somewhere/else" }), p.alphaDID, "EALPHA", "EBETA", now, ErrKind},
		{"an identifier with a line break", sealed(func(pt *parts) { pt.st.ToAgent = "EV\nERT" }), p.alphaDID, "EALPHA", "EBETA", now, ErrField},
		{"an identifier with a terminal escape", sealed(func(pt *parts) { pt.st.FromAgent = "E\x1b[2J" }), p.alphaDID, "EALPHA", "EBETA", now, ErrField},
		{"an identifier with a text-direction override", sealed(func(pt *parts) { pt.st.MessageID = "m‮1" }), p.alphaDID, "EALPHA", "EBETA", now, ErrField},
		{"a message named like an entry's place", sealed(func(pt *parts) { pt.st.MessageID = "e1" }), p.alphaDID, "EALPHA", "EBETA", now, ErrPlaceID},
		{"the sender named is not the signer", sealed(func(pt *parts) { pt.st.FromAID = "EBETA" }), p.alphaDID, "EALPHA", "EBETA", now, ErrWrongSender},
		{"an extra field in the content", sealed(func(pt *parts) {
			a, _ := pt.st.attributes()
			pt.data = strings.TrimSuffix(string(a), "}") + `,"also":"this"}`
		}), p.alphaDID, "EALPHA", "EBETA", now, ErrUnreadable},
		{"a modifier", sealed(func(pt *parts) { pt.modifiers = json.RawMessage(`{"x":"y"}`) }), p.alphaDID, "EALPHA", "EBETA", now, ErrNotInItsOneForm},
		{"a prior message", sealed(func(pt *parts) { pt.prior = "EKkPEUZ6Ihm-JvBBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0" }), p.alphaDID, "EALPHA", "EBETA", now, ErrNotInItsOneForm},
		{"the unsalted fingerprint version", sealed(func(pt *parts) {
			a, _ := pt.st.attributes()
			pt.data = strings.Replace(string(a), `"fingerprint_version":1`, `"fingerprint_version":0`, 1)
		}), p.alphaDID, "EALPHA", "EBETA", now, ErrFingerprintVer},
		{"a fingerprint that is not a digest", sealed(func(pt *parts) { pt.st.Fingerprint = "not-a-digest" }), p.alphaDID, "EALPHA", "EBETA", now, ErrFingerprint},
		{"a date in another spelling", sealed(func(pt *parts) { pt.st.SentAt = "2026-11-14T12:00:00Z" }), p.alphaDID, "EALPHA", "EBETA", now, ErrTime},
	}
	for _, c := range cases {
		_, err := Verify(c.msg, c.signer, c.by, c.self, c.at)
		if err != error(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
			continue
		}
		if CodeOf(err) != c.want.Code() || c.want.Code() == "" {
			t.Errorf("%s: code %q", c.name, CodeOf(err))
		}
	}
}

// A reply, a failure and a progress note each name the ask they answer.
func TestARepliesFailuresAndProgressNameTheirAsk(t *testing.T) {
	p := newPair(t)
	for _, k := range []string{KindReply, KindFailure, KindProgress} {
		st := ask()
		st.Kind, st.InReplyTo = k, "m-0"
		m, err := Seal(p.alpha, st, "answer", now)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if s, err := Verify(m, p.alphaDID, "EALPHA", "EBETA", now); err != nil || s.InReplyTo != "m-0" || s.Kind != k {
			t.Errorf("%s: %v %+v", k, err, s)
		}
		st.InReplyTo = ""
		if _, err := Seal(p.alpha, st, "answer", now); err != error(ErrReplyTo) {
			t.Errorf("%s answering nothing was sealed: %v", k, err)
		}
	}
}

// A sender cannot seal a message as somebody else: the statement's sender is
// always the keyset that signs it.
func TestASenderCannotSealAsAnotherIdentityAgent(t *testing.T) {
	p := newPair(t)
	st := ask()
	st.FromAID = "EBETA"
	m, err := Seal(p.alpha, st, "x", now)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := Verify(m, p.alphaDID, "EALPHA", "EBETA", now); err != nil || s.FromAID != "EALPHA" {
		t.Fatalf("sealed as %v: %v", s.FromAID, err)
	}
}

// Words of any size beyond the limit are not sealed.
func TestWordsAreBounded(t *testing.T) {
	p := newPair(t)
	if _, err := Seal(p.alpha, ask(), strings.Repeat("x", MaxWords+1), now); err != error(ErrWords) {
		t.Fatal(err)
	}
	if _, err := Seal(p.alpha, ask(), "", now); err != error(ErrWords) {
		t.Fatal(err)
	}
}

// The limits on what an identifier may be, and on the salt, are each held.
func TestTheLimitsOnIdentifiersAndSaltsAreHeld(t *testing.T) {
	good := func(s string) bool { return plain(s) }
	if !good(strings.Repeat("a", 128)) || good(strings.Repeat("a", 129)) {
		t.Error("the 128 character limit is not the limit")
	}
	if !good("a:b.c_d-e") || good("a/b") || good("a b") || good("") || good("é") {
		t.Error("the identifier alphabet is not the alphabet")
	}
	p := newPair(t)
	m, _ := Seal(p.alpha, ask(), "x", now)
	long := base64.RawURLEncoding.EncodeToString(make([]byte, fingerprint.MaxSalt+1))
	m.Salt = long
	if _, err := Verify(m, p.alphaDID, "EALPHA", "EBETA", now); err != error(ErrSalt) {
		t.Errorf("a salt over the maximum: %v", err)
	}
	m, _ = Seal(p.alpha, ask(), "x", now)
	m.Salt += "="
	if _, err := Verify(m, p.alphaDID, "EALPHA", "EBETA", now); err != error(ErrSalt) {
		t.Errorf("a padded salt: %v", err)
	}
	m, _ = Seal(p.alpha, ask(), "x", now)
	m.Words = strings.Repeat("x", MaxWords+1)
	if _, err := Verify(m, p.alphaDID, "EALPHA", "EBETA", now); err != error(ErrWords) {
		t.Errorf("words over the limit in Verify: %v", err)
	}
	// The reply's own name may not take an entry's place either.
	st := ask()
	st.Kind, st.InReplyTo = KindReply, "e7"
	if _, err := Seal(p.alpha, st, "x", now); err != error(ErrPlaceID) {
		t.Errorf("an answer naming a place: %v", err)
	}
	// Another Identity Agent's identifier in the statement than the one that signs.
	pt, salt := goodParts(t, "EBETA", "words")
	other := pt.sealWith(t, p.alpha, "words", salt)
	if _, err := ReadStatement(other.Signed, p.alphaDID); err != error(ErrWrongSender) {
		t.Errorf("a statement naming another sender: %v", err)
	}
}
