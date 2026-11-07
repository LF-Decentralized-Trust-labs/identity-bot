package conversationbundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
	"identity-agent-core/trail"
)

// A person's entries, their refusals and how each ended are entries of the
// conversation's one chain, checked by this verifier and no other (ADR-068).
// These write a conversation with the real trail and check what it wrote.

type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) PublicKey() ([]byte, error)    { return s.priv.Public().(ed25519.PublicKey), nil }
func (s edSigner) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.priv, d), nil }

// allowAll lets everything through; bot, when set, is the AI agent that
// IsAIAgent knows beside EBOT.
type allowAll struct{ bot string }

func (allowAll) KeySpeaksFor(string, string, string) bool { return true }
func (a allowAll) IsAIAgent(id string) bool               { return id == "EBOT" || a.bot != "" && id == a.bot }
func (allowAll) MayUseAgent(string, string) bool          { return true }
func (allowAll) AgentGrantAllows(string, string) bool     { return true }
func (allowAll) ActiveEmployee(string) bool               { return true }
func (allowAll) IsSigner(string) bool                     { return false }

type keepingApp struct {
	fail  bool
	wrong bool
}

func (keepingApp) Reachable(context.Context) error { return nil }
func (a keepingApp) Keep(_ context.Context, f trail.Forward) (trail.Receipt, error) {
	if a.fail {
		return trail.Receipt{}, fmt.Errorf("no")
	}
	fp, _ := agentmessage.Fingerprint(f.Salt, f.Words)
	if a.wrong {
		fp = "Ewrong"
	}
	return trail.Receipt{Fingerprint: fp}, nil
}
func (keepingApp) Discard(context.Context, string, string) error { return nil }

const rootAID = "EROOT"

type kept struct{ salt, words []byte }

// conversation is a written conversation: its chain, and the words and salts
// the app holds under each entry id.
type conversation struct {
	t     *testing.T
	tr    *trail.Trail
	keys  *didcomm.KeySet
	app   *keepingApp
	now   time.Time
	n     int
	words map[string]kept
	// root is the Identity Agent's identifier, and bot the AI agent a person
	// addresses. They are the placeholders rootAID and EBOT unless the
	// conversation is written in a whole world (aWorld), where they are real.
	root, bot string
	world     *theWorld
}

func newConversation(t *testing.T) *conversation {
	t.Helper()
	return newConversationWith(t, allowAll{}, nil)
}

// newConversationWith is newConversation with another roster, and with an app
// that can also be read when backend is given a constructor for it.
func newConversationWith(t *testing.T, roster trail.Roster, backend func(*conversation) trail.Backend) *conversation {
	t.Helper()
	return newConversationIn(t, roster, backend, rootAID, "EBOT")
}

// newConversationIn is newConversationWith for an Identity Agent named root,
// and an AI agent named bot.
func newConversationIn(t *testing.T, roster trail.Roster, backend func(*conversation) trail.Backend, root, bot string) *conversation {
	t.Helper()
	keys, err := didcomm.GenerateKeySet(root)
	if err != nil {
		t.Fatal(err)
	}
	c := &conversation{t: t, keys: keys, app: &keepingApp{}, now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC), words: map[string]kept{}, root: root, bot: bot}
	var be trail.Backend = c.app
	if backend != nil {
		be = backend(c)
	}
	c.tr = trail.New(roster, be, trail.Options{Agent: root, Now: func() time.Time { c.now = c.now.Add(time.Second); return c.now },
		Countersign: func(r agentmessage.Record) (*didcomm.Envelope, error) { return agentmessage.Countersign(keys, r) }})
	if err := c.tr.Open("c1", "EALICE", true); err != nil {
		t.Fatal(err)
	}
	return c
}

// say writes one message from a person. edit changes the statement before it
// is signed.
func (c *conversation) say(from, words string, edit func(*agentmessage.PersonStatement)) trail.Result {
	c.t.Helper()
	res, err := c.trySay(from, words, edit)
	if err != nil {
		c.t.Fatal(err)
	}
	return res
}

// trySay is say, returning the error a rejected write gives.
func (c *conversation) trySay(from, words string, edit func(*agentmessage.PersonStatement)) (trail.Result, error) {
	c.t.Helper()
	c.n++
	signer := edSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))}
	id, verkey, _ := agentbody.Identity(signer)
	salt := bytes.Repeat([]byte{byte(c.n)}, agentmessage.MinSalt)
	fp, err := agentmessage.Fingerprint(salt, []byte(words))
	if err != nil {
		c.t.Fatal(err)
	}
	s := agentmessage.PersonStatement{Agent: c.root, Conversation: "c1", MessageID: fmt.Sprintf("m%d", c.n), Kind: "message", From: from,
		Signer: id, To: c.bot, Nonce: fmt.Sprintf("nonce-%016d", c.n), Time: c.now.Add(time.Second).Format(time.RFC3339),
		FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: fp}
	if edit != nil {
		edit(&s)
	}
	sig, err := agentmessage.SignPerson(signer, s)
	if err != nil {
		c.t.Fatal(err)
	}
	res, err := c.tr.Write(context.Background(), trail.Write{Statement: s, Verkey: verkey, Signature: sig, Salt: salt, Words: []byte(words)})
	if err != nil {
		return res, err
	}
	if res.State == trail.Committed {
		// The app keeps the words of a kept entry only: a refusal never reached
		// it, and it was told to discard what it did not keep.
		c.words[res.EntryID] = kept{salt, []byte(words)}
	}
	return res, nil
}

// bundle is the conversation as an export carries it. withWords puts the
// words in beside the entries that have them.
func (c *conversation) bundle(withWords bool) *Bundle {
	b := &Bundle{Format: Format, Conversation: "c1", Root: c.root}
	for _, e := range c.tr.Chain("c1") {
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
	v.dids = map[string]*didcomm.DID{c.root: did}
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
	if dup.State != trail.Refused {
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
		for _, e := range c.tr.Chain("c1") {
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
	salted := mustRead(t, c.tr.Chain("c1")[0].Envelope)
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
	if got := faults(salted, agentEntry, mustRead(t, c.tr.Chain("c1")[1].Envelope)); got != "" {
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
	for _, e := range c.tr.Chain("c1") {
		rs = append(rs, mustRead(t, e.Envelope))
	}
	return rs
}
