package conversationbundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

// A person's entries, their refusals and how each ended are entries of the
// conversation's one chain, checked by this verifier and no other (ADR-068).
// These write a conversation by hand, as the contract describes one, and check
// what was written. That the add-on that keeps trails writes the same is its own
// test, against this verifier.

type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) PublicKey() ([]byte, error)    { return s.priv.Public().(ed25519.PublicKey), nil }
func (s edSigner) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.priv, d), nil }

// keepingApp stands for the app that keeps the words: wrong makes it answer
// with a fingerprint that is not the one signed, so the entry is not kept.
type keepingApp struct{ wrong bool }

// How a written entry stood at the end, as the chain says it.
const (
	committed = "committed"
	refused   = "refused"
	notKept   = "not-kept"
)

type result struct{ EntryID, State string }

const rootAID = "EROOT"

type kept struct{ salt, words []byte }

// conversation is a written conversation: its chain, and the words and salts
// the app holds under each entry id. The chain is written here by hand, as
// ../contracts/trail/trail.md describes it (a person's entry, then the Identity
// Agent's outcome after it; a refusal has none), because keeping a trail is an
// add-on's (ADR-068) and this package only checks one.
type conversation struct {
	t     *testing.T
	keys  *didcomm.KeySet
	app   *keepingApp
	now   time.Time
	n     int
	chain []agentmessage.Entry
	words map[string]kept
	// seen is the ids a person has used, to refuse the reuse of one.
	seen map[string]bool
}

func newConversation(t *testing.T) *conversation {
	t.Helper()
	keys, err := didcomm.GenerateKeySet(rootAID)
	if err != nil {
		t.Fatal(err)
	}
	return &conversation{t: t, keys: keys, app: &keepingApp{}, now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC),
		words: map[string]kept{}, seen: map[string]bool{}}
}

// append countersigns a record as the next entry of the chain.
func (c *conversation) append(rec agentmessage.Record) agentmessage.Entry {
	c.t.Helper()
	c.now = c.now.Add(time.Second)
	rec.Conversation, rec.Seq, rec.IATime = "c1", len(c.chain)+1, c.now.UTC().Format(time.RFC3339Nano)
	rec.MessageID, rec.OpenedBy = agentmessage.EntryID(rec.Seq), agentmessage.Person("EALICE")
	if n := len(c.chain); n > 0 {
		rec.PrevHash = c.chain[n-1].Hash
	}
	env, err := agentmessage.Countersign(c.keys, rec)
	if err != nil {
		c.t.Fatal(err)
	}
	e := agentmessage.Entry{Conversation: "c1", Seq: rec.Seq, MessageID: rec.MessageID, Kind: rec.Kind, From: rec.From, To: rec.To,
		InReplyTo: rec.InReplyTo, BodyHash: rec.BodyHash, ContentRef: rec.MessageID, Envelope: env, Hash: agentmessage.Hash(env), CreatedAt: c.now.UTC()}
	c.chain = append(c.chain, e)
	return e
}

// ends writes how entry ended: the Identity Agent's outcome record after it.
func (c *conversation) ends(entry, state, reason string) {
	c.t.Helper()
	c.append(agentmessage.Record{Kind: agentmessage.KindOutcome, From: rootAID, InReplyTo: entry, BodyHash: agentmessage.HashBody(nil),
		Outcome: &agentmessage.Outcome{Entry: entry, State: state, Reason: reason}})
}

// say writes one message from a person. edit changes the statement before it
// is signed.
func (c *conversation) say(from, words string, edit func(*agentmessage.PersonStatement)) result {
	c.t.Helper()
	c.n++
	signer := edSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))}
	id, verkey, _ := agentbody.Identity(signer)
	salt := bytes.Repeat([]byte{byte(c.n)}, agentmessage.MinSalt)
	fp, err := agentmessage.Fingerprint(salt, []byte(words))
	if err != nil {
		c.t.Fatal(err)
	}
	s := agentmessage.PersonStatement{Agent: rootAID, Conversation: "c1", MessageID: fmt.Sprintf("m%d", c.n), Kind: "message", From: from,
		Signer: id, To: "EBOT", Nonce: fmt.Sprintf("nonce-%016d", c.n), Time: c.now.Add(time.Second).Format(time.RFC3339),
		FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: fp}
	if edit != nil {
		edit(&s)
	}
	sig, err := agentmessage.SignPerson(signer, s)
	if err != nil {
		c.t.Fatal(err)
	}
	rec := agentmessage.Record{
		Kind: s.Kind, From: agentmessage.Person(s.From), To: s.To, InReplyTo: s.InReplyTo, BodyHash: s.Fingerprint,
		PersonProof: &agentmessage.PersonProof{Statement: s, Verkey: verkey, Signature: sig},
	}
	used := s.From + "\n" + s.MessageID
	if c.seen[used] {
		// The reuse of an id is a refusal, which has no outcome and uses up
		// the nonce too.
		rec.Refusal = "id already used"
		e := c.append(rec)
		return result{e.MessageID, refused}
	}
	c.seen[used] = true
	if from != "EALICE" {
		// Only the conversation's owner may write; anyone else is refused.
		rec.Refusal = "only the conversation's owner may do that"
		e := c.append(rec)
		return result{e.MessageID, refused}
	}
	e := c.append(rec)
	if c.app.wrong {
		c.ends(e.MessageID, notKept, "the app's confirmation did not match what was sent")
		return result{e.MessageID, notKept}
	}
	c.ends(e.MessageID, committed, "")
	// The app keeps the words of a kept entry only.
	c.words[e.MessageID] = kept{salt, []byte(words)}
	return result{e.MessageID, committed}
}

// bundle is the conversation as an export carries it. withWords puts the
// words in beside the entries that have them.
func (c *conversation) bundle(withWords bool) *Bundle {
	b := &Bundle{Format: Format, Conversation: "c1", Root: rootAID}
	for _, e := range c.chain {
		x := Entry{Envelope: e.Envelope}
		if k, ok := c.words[e.MessageID]; ok && withWords {
			x.Body, x.Salt = base64.StdEncoding.EncodeToString(k.words), base64.StdEncoding.EncodeToString(k.salt)
		}
		b.Entries = append(b.Entries, x)
	}
	return b
}

// check runs the verifier's entry checks over a bundle, with the Identity
// Agent's messaging keys as the key log would give them.
func (c *conversation) check(b *Bundle) *verifier {
	c.t.Helper()
	did, err := c.keys.DID()
	if err != nil {
		c.t.Fatal(err)
	}
	v := newVerifier()
	v.b, v.hashes, v.signedOnce, v.answered, v.notes = b, map[int]string{}, map[string]int{}, map[string]bool{}, map[string]bool{}
	v.dids = map[string]*didcomm.DID{rootAID: did}
	v.checkEntries()
	return v
}

// The conversation these use: e1 committed (e2 its outcome), e3 refused, e4
// not kept (e5 its outcome), e6 committed (e7 its outcome).
func writeMixed(c *conversation) {
	c.say("EALICE", "one", nil)
	c.say("EBOB", "two", nil)
	c.app.wrong = true
	c.say("EALICE", "three", nil)
	c.app.wrong = false
	c.say("EALICE", "four", func(s *agentmessage.PersonStatement) { s.InReplyTo = "e1" })
}

func TestAConversationOfPersonEntriesVerifiesInTheOneChain(t *testing.T) {
	c := newConversation(t)
	// Bob is not the owner, so his entry is a refusal, which allowAll does not
	// decide; make it one by reusing an id instead.
	c.say("EALICE", "one", nil)
	dup := c.say("EALICE", "two", func(s *agentmessage.PersonStatement) { s.MessageID = "m1" })
	if dup.State != refused {
		t.Fatalf("the reuse of an id was %s", dup.State)
	}
	c.app.wrong = true
	c.say("EALICE", "three", nil)
	c.app.wrong = false
	c.say("EALICE", "four", func(s *agentmessage.PersonStatement) { s.InReplyTo = "e1" })

	v := c.check(c.bundle(true))
	if len(v.r.Faults) != 0 {
		t.Fatalf("a good conversation has faults: %s", openingFaults(v))
	}
	if n := len(v.r.Messages); n != 7 {
		t.Fatalf("the report covers %d entries, want 7", n)
	}
	for i, want := range []string{"statement", "identity agent", "statement", "statement", "identity agent", "statement", "identity agent"} {
		if got := v.r.Messages[i].Sender; got != want {
			t.Fatalf("entry %d is from %q, want %q", i+1, got, want)
		}
	}
	// Without the app's words the entries still verify; the report says it
	// could not recompute the fingerprints.
	v = c.check(c.bundle(false))
	if len(v.r.Faults) != 0 || !strings.Contains(strings.Join(v.r.CannotRuleOut, "\n"), "not in the bundle") {
		t.Fatalf("a bundle without the app's words: faults %s, notes %v", openingFaults(v), v.r.CannotRuleOut)
	}
}

func TestEachKindOfTamperingWithPersonEntriesIsCaught(t *testing.T) {
	flip := func(s string) string {
		raw, _ := base64.StdEncoding.DecodeString(s)
		raw[0] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}
	for name, tc := range map[string]struct {
		change func(b *Bundle)
		want   string
	}{
		"changed words":        {func(b *Bundle) { b.Entries[0].Body = flip(b.Entries[0].Body) }, "not the words it was signed over"},
		"changed salt":         {func(b *Bundle) { b.Entries[0].Salt = flip(b.Entries[0].Salt) }, "not the words it was signed over"},
		"words without a salt": {func(b *Bundle) { b.Entries[0].Salt = "" }, "without the salt"},
		"words for a refusal": {func(b *Bundle) {
			b.Entries[2].Body = base64.StdEncoding.EncodeToString([]byte("x"))
			b.Entries[2].Salt = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
		}, "no words are expected"},
		"an entry removed":         {func(b *Bundle) { b.Entries = append(b.Entries[:1], b.Entries[2:]...) }, "entry before it is missing"},
		"entries out of order":     {func(b *Bundle) { b.Entries[0], b.Entries[1] = b.Entries[1], b.Entries[0] }, "missing or out of place"},
		"a countersignature":       {func(b *Bundle) { b.Entries[1].Envelope.EdSig = b.Entries[0].Envelope.EdSig }, "not countersigned"},
		"an outcome made up twice": {func(b *Bundle) { b.Entries = append(b.Entries, b.Entries[1]) }, "appears twice"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newConversation(t)
			writeMixed(c)
			b := c.bundle(true)
			if len(c.check(b).r.Faults) != 0 {
				t.Fatalf("the untouched conversation has faults: %s", openingFaults(c.check(b)))
			}
			tc.change(b)
			if got := openingFaults(c.check(b)); !strings.Contains(got, tc.want) {
				t.Fatalf("tampering went unnoticed or was named wrongly (want %q): %q", tc.want, got)
			}
		})
	}
}

// What the Identity Agent itself signs is checked against the chain: an
// outcome for an entry that is not there, one that ends an entry twice, and
// one that is not the Identity Agent's are all faults.
func TestAnOutcomeIsHeldToTheChain(t *testing.T) {
	c := newConversation(t)
	c.say("EALICE", "one", nil) // e1, and its outcome e2
	records := func() []agentmessage.Record {
		var rs []agentmessage.Record
		for _, e := range c.chain {
			r, err := agentmessage.Read(e.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			rs = append(rs, r)
		}
		return rs
	}
	for name, tc := range map[string]struct {
		edit func(rs []agentmessage.Record) []agentmessage.Record
		want string
	}{
		"an outcome for an entry that is not there": {func(rs []agentmessage.Record) []agentmessage.Record {
			rs[1].Outcome.Entry, rs[1].InReplyTo = "e9", "e9"
			return rs
		}, "not an earlier entry"},
		"an entry ended twice": {func(rs []agentmessage.Record) []agentmessage.Record {
			o := rs[1]
			o.MessageID = "e3"
			return append(rs, o)
		}, "already committed"},
		"an outcome from someone else": {func(rs []agentmessage.Record) []agentmessage.Record {
			rs[1].From = "EOTHER"
			return rs
		}, "no messaging keys tied to EOTHER"},
	} {
		t.Run(name, func(t *testing.T) {
			b := c.rebuilt(tc.edit(records()))
			if got := openingFaults(c.check(b)); !strings.Contains(got, tc.want) {
				t.Fatalf("want a fault containing %q, got %q", tc.want, got)
			}
		})
	}
	if got := openingFaults(c.check(c.rebuilt(records()))); got != "" {
		t.Fatalf("the unedited records have faults: %s", got)
	}
}

// rebuilt countersigns records afresh as the next entries of a chain, so an
// edit to a record is still a validly countersigned, correctly chained entry.
func (c *conversation) rebuilt(rs []agentmessage.Record) *Bundle {
	c.t.Helper()
	b := &Bundle{Format: Format, Conversation: "c1", Root: rootAID}
	prev := ""
	for i := range rs {
		rs[i].Seq, rs[i].PrevHash = i+1, prev
		env, err := agentmessage.Countersign(c.keys, rs[i])
		if err != nil {
			c.t.Fatal(err)
		}
		prev = agentmessage.Hash(env)
		x := Entry{Envelope: env}
		if k, ok := c.words[rs[i].MessageID]; ok && rs[i].PersonProof != nil {
			x.Body, x.Salt = base64.StdEncoding.EncodeToString(k.words), base64.StdEncoding.EncodeToString(k.salt)
		}
		b.Entries = append(b.Entries, x)
	}
	return b
}

// A person's unsalted words are old only before the first salted entry
// (ADR-067). The records that really hold them are the ones a paired app's
// signed request made, so this is tried on the published genuine export's own
// records, not on a statement that says version 0.
func TestUnsaltedWordsAfterASaltedEntryAreAFault(t *testing.T) {
	_, genuine := theVector(t)
	old, err := agentmessage.Read(genuine.Entries[0].Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if v, person := old.FingerprintVersion(); !person || v != agentmessage.FingerprintV0 {
		t.Fatalf("the genuine person's record is version %d (a person's: %v), want 0", v, person)
	}
	if _, person := mustRead(t, genuine.Entries[2].Envelope).FingerprintVersion(); person {
		t.Fatal("an AI agent's entry is counted as a person's words")
	}

	c := newConversation(t)
	c.say("EALICE", "one", nil) // e1 salted, e2 its outcome
	salted := mustRead(t, c.chain[0].Envelope)
	if v, person := salted.FingerprintVersion(); !person || v != agentmessage.FingerprintV1 {
		t.Fatalf("a person's statement is version %d", v)
	}

	faults := func(recs ...agentmessage.Record) string {
		v := newVerifier()
		for i, r := range recs {
			v.checkVersionOrder(fmt.Sprintf("entry %d", i+1), r)
		}
		return openingFaults(v)
	}
	if got := faults(old, old, salted); got != "" {
		t.Fatalf("unsalted words before a salted entry were a fault: %s", got)
	}
	if got := faults(old, salted, old); !strings.Contains(got, "entry 3") || !strings.Contains(got, "unsalted") {
		t.Fatalf("unsalted words after a salted entry were not a fault at entry 3: %q", got)
	}
	agentEntry := mustRead(t, genuine.Entries[2].Envelope)
	if got := faults(salted, agentEntry, mustRead(t, c.chain[1].Envelope)); got != "" {
		t.Fatalf("an AI agent's entry or an outcome after a salted one was a fault: %s", got)
	}

	// Through the verifier's whole entry check: the genuine person's record,
	// countersigned again as the entry after a salted one.
	next := old
	next.Conversation, next.OpenedBy = "c1", salted.OpenedBy
	b := c.rebuilt(append(recordsOf(t, c), next))
	if got := openingFaults(c.check(b)); !strings.Contains(got, "entry 3: the person's words are unsalted (version 0)") {
		t.Fatalf("an unsalted entry after a salted one was not named by the verifier: %q", got)
	}
}

func mustRead(t *testing.T, env *didcomm.Envelope) agentmessage.Record {
	t.Helper()
	r, err := agentmessage.Read(env)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func recordsOf(t *testing.T, c *conversation) []agentmessage.Record {
	var rs []agentmessage.Record
	for _, e := range c.chain {
		rs = append(rs, mustRead(t, e.Envelope))
	}
	return rs
}

// An entry whose message was not delivered is noted once, after a kept entry, by
// the Identity Agent, and the conversation still verifies; a note about an entry
// that was not kept, or a second note, is a fault.
func TestANotDeliveredNoteFollowsAKeptEntryOnce(t *testing.T) {
	c := newConversation(t)
	writeMixed(c) // e1 committed, e3 refused, e4 not kept, e6 committed
	c.ends("e1", agentmessage.OutcomeNotDelivered, "the recipient was not reachable for 7 days")
	if got := openingFaults(c.check(c.bundle(true))); got != "" {
		t.Fatalf("a not-delivered note is a fault: %s", got)
	}
	// A trail refuses what the verifier would, so the bad chains are built by hand.
	records := func() []agentmessage.Record {
		var rs []agentmessage.Record
		for _, e := range c.chain {
			rs = append(rs, mustRead(t, e.Envelope))
		}
		return rs
	}
	extra := func(entry string) []agentmessage.Record {
		rs := records()
		n := rs[len(rs)-1] // the real note, copied
		o := *n.Outcome
		o.Entry = entry
		n.Outcome, n.InReplyTo, n.MessageID = &o, entry, agentmessage.EntryID(len(rs)+1)
		return append(rs, n)
	}
	for name, tc := range map[string]struct {
		rs   []agentmessage.Record
		want string
	}{
		"a second note":        {extra("e1"), "delivery fails once"},
		"an entry refused":     {extra("e3"), "delivery fails once"},
		"an entry not kept":    {extra("e4"), "delivery fails once"},
		"an entry not written": {extra("e90"), "not an earlier entry"},
	} {
		if got := openingFaults(c.check(c.rebuilt(tc.rs))); !strings.Contains(got, tc.want) {
			t.Errorf("%s: want a fault containing %q, got %q", name, tc.want, got)
		}
	}
}
