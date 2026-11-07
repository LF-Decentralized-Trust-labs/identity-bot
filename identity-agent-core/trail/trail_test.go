package trail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) PublicKey() ([]byte, error)    { return s.priv.Public().(ed25519.PublicKey), nil }
func (s edSigner) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.priv, d), nil }

func signerOf(b byte) edSigner {
	return edSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))}
}

// roster is a Roster whose answers a test sets.
type roster struct {
	keys      map[string]string // person -> signer identifier
	agents    map[string]bool
	reach     map[string]bool // person+"\n"+agent
	employees map[string]bool
	signers   map[string]bool
	noGrant   map[string]bool // person+"\n"+agent the agent's grant refuses
}

func (r *roster) KeySpeaksFor(person, signer, _ string) bool { return r.keys[person] == signer }
func (r *roster) IsAIAgent(id string) bool                   { return r.agents[id] }
func (r *roster) MayUseAgent(p, a string) bool               { return r.reach[p+"\n"+a] }
func (r *roster) AgentGrantAllows(a, p string) bool          { return !r.noGrant[p+"\n"+a] }
func (r *roster) ActiveEmployee(p string) bool               { return r.employees[p] }
func (r *roster) IsSigner(p string) bool                     { return r.signers[p] }

// app is a Backend that records what reached it.
type app struct {
	mu        sync.Mutex
	down      bool
	refuse    bool
	wrongFP   bool
	hang      bool
	kept      map[string]Forward
	keepCalls int
	discarded []string
	extra     map[string]Stored
}

func (a *app) Reachable(context.Context) error {
	if a.down {
		return ErrUnreachable
	}
	return nil
}

func (a *app) Keep(ctx context.Context, f Forward) (Receipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keepCalls++
	if a.hang {
		<-ctx.Done()
		return Receipt{}, ctx.Err()
	}
	if a.refuse {
		return Receipt{}, fmt.Errorf("no")
	}
	if a.kept == nil {
		a.kept = map[string]Forward{}
	}
	a.kept[f.EntryID] = f
	fp, _ := agentmessage.Fingerprint(f.Salt, f.Words)
	if a.wrongFP {
		fp = "Ewrong"
	}
	return Receipt{Fingerprint: fp}, nil
}

func (a *app) Discard(_ context.Context, _, id string) error {
	a.discarded = append(a.discarded, id)
	return nil
}

type fixture struct {
	t      *testing.T
	keys   *didcomm.KeySet
	tr     *Trail
	app    *app
	roster *roster
	n      int
	now    time.Time
}

const (
	alice = "EALICE"
	bob   = "EBOB"
	boss  = "EBOSS"
	bot   = "EBOT"
	bot2  = "EBOT2"
)

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, app: &app{}, now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	f.roster = &roster{
		keys:      map[string]string{},
		agents:    map[string]bool{bot: true, bot2: true},
		reach:     map[string]bool{alice + "\n" + bot: true, bob + "\n" + bot: true},
		employees: map[string]bool{bob: true},
		signers:   map[string]bool{boss: true},
		noGrant:   map[string]bool{},
	}
	for i, p := range []string{alice, bob, boss} {
		id, _, _ := agentbody.Identity(signerOf(byte(i + 1)))
		f.roster.keys[p] = id
	}
	keys, err := didcomm.GenerateKeySet(testAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.keys = keys
	f.tr = New(f.roster, f.app, Options{Agent: testAgent, ForwardTimeout: 50 * time.Millisecond, Now: func() time.Time { return f.now },
		Countersign: func(r agentmessage.Record) (*didcomm.Envelope, error) { return agentmessage.Countersign(keys, r) }})
	if err := f.tr.Open("c1", alice, true); err != nil {
		t.Fatal(err)
	}
	return f
}

const testAgent = "EIDENTITYAGENT"

var keyIndex = map[string]byte{alice: 1, bob: 2, boss: 3}

// say builds a signed write by a person. Each call has a fresh id and nonce
// unless the statement is changed afterwards.
func (f *fixture) say(from, kind, to, words string, edit func(*agentmessage.PersonStatement)) Write {
	f.t.Helper()
	f.n++
	signer := signerOf(keyIndex[from])
	id, verkey, _ := agentbody.Identity(signer)
	salt := bytes.Repeat([]byte{byte(f.n)}, agentmessage.MinSalt)
	fp, err := agentmessage.Fingerprint(salt, []byte(words))
	if err != nil {
		f.t.Fatal(err)
	}
	s := agentmessage.PersonStatement{
		Agent: testAgent, Conversation: "c1", MessageID: fmt.Sprintf("m%d", f.n), Kind: kind, From: from, Signer: id, To: to,
		Nonce: fmt.Sprintf("nonce-%016d", f.n), Time: "2026-11-06T12:00:00Z",
		FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: fp,
	}
	if edit != nil {
		edit(&s)
	}
	sig, err := agentmessage.SignPerson(signer, s)
	if err != nil {
		f.t.Fatal(err)
	}
	return Write{Statement: s, Verkey: verkey, Signature: sig, Salt: salt, Words: []byte(words)}
}

func (f *fixture) write(w Write) Result {
	f.t.Helper()
	r, err := f.tr.Write(context.Background(), w)
	if err != nil {
		f.t.Fatalf("write: %v", err)
	}
	return r
}

// A refused message never reaches the app: the app is not called, the trail
// holds a refusal with no words, and the words appear nowhere in it.
func TestARefusedMessageNeverReachesTheApp(t *testing.T) {
	const secret = "the-secret-words-of-a-refused-message"
	cases := map[string]func(f *fixture) Write{
		"a person who is not the owner": func(f *fixture) Write { return f.say(bob, "message", bot, secret, nil) },
		"an agent the person may not use": func(f *fixture) Write {
			return f.say(alice, "message", bot2, secret, nil)
		},
		"words that are not the ones signed": func(f *fixture) Write {
			w := f.say(alice, "message", bot, "what was signed", nil)
			w.Words = []byte(secret)
			return w
		},
		"the app being unreachable": func(f *fixture) Write {
			f.app.down = true
			return f.say(alice, "message", bot, secret, nil)
		},
		"an answer to a message that is not there": func(f *fixture) Write {
			return f.say(alice, "message", bot, secret, func(s *agentmessage.PersonStatement) { s.InReplyTo = "e99" })
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			res := f.write(mk(f))
			if res.State != Refused || res.Reason == "" {
				t.Fatalf("got %+v, want a refusal with a reason", res)
			}
			if f.app.keepCalls != 0 || len(f.app.kept) != 0 {
				t.Fatal("a refused message reached the app")
			}
			es := f.tr.Entries("c1")
			if len(es) != 1 || es[0].State() != Refused {
				t.Fatalf("want one refusal in the trail, got %d entries", len(es))
			}
			raw, _ := json.Marshal(es)
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatal("the words of a refused message are in the trail")
			}
			if recs := f.chainOf("c1"); len(recs) != 1 || recs[0].Refusal == "" || recs[0].CheckSenderProof() != nil {
				t.Fatal("a refusal is not an entry of the chain with its author's proof")
			}
			if len(f.tr.Committed("c1")) != 0 {
				t.Fatal("a refusal is delivered")
			}
		})
	}
}

func TestACommittedEntryIsKeptByTheAppAndDelivered(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "hello", nil)
	res := f.write(w)
	if res.State != Committed || res.EntryID != "e1" {
		t.Fatalf("got %+v", res)
	}
	got := f.app.kept["e1"]
	if string(got.Words) != "hello" || !bytes.Equal(got.Salt, w.Salt) {
		t.Fatal("the app was not given the words and salt")
	}
	if len(f.tr.Committed("c1")) != 1 {
		t.Fatal("a committed entry is not delivered")
	}
	raw, _ := json.Marshal(f.tr.Entries("c1"))
	if bytes.Contains(raw, []byte("hello")) {
		t.Fatal("the trail holds the words")
	}
}

// A retried message id is kept once.
func TestARetriedMessageIDIsKeptOnce(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "hello", nil)
	first := f.write(w)
	again := f.write(w)
	if !again.Replayed || again.EntryID != first.EntryID || again.State != Committed {
		t.Fatalf("retry returned %+v, first %+v", again, first)
	}
	if f.app.keepCalls != 1 || len(f.tr.Entries("c1")) != 1 {
		t.Fatalf("kept %d times, %d entries; want once", f.app.keepCalls, len(f.tr.Entries("c1")))
	}
}

// The same id with a different statement is refused; the identical statement
// returns the earlier result. Both hold for a refusal and a not-kept entry too.
func TestTheSameIDWithADifferentStatementIsRefused(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "hello", nil)
	first := f.write(w)

	other := f.say(alice, "message", bot, "something else", func(s *agentmessage.PersonStatement) { s.MessageID = w.Statement.MessageID })
	res := f.write(other)
	if res.State != Refused || res.Reason != ReasonIDUsed {
		t.Fatalf("got %+v, want %q", res, ReasonIDUsed)
	}
	if f.app.keepCalls != 1 {
		t.Fatal("the different statement reached the app")
	}
	if _, ok := f.app.kept[res.EntryID]; ok {
		t.Fatal("words kept under the refusal")
	}
	// Repeating the same different statement does not grow the trail.
	if again := f.write(other); again.EntryID != res.EntryID || !again.Replayed {
		t.Fatalf("repeat of the refused statement: %+v", again)
	}
	// The original id still returns the earlier result.
	if back := f.write(w); back.EntryID != first.EntryID || back.State != Committed || !back.Replayed {
		t.Fatalf("the earlier result was lost: %+v", back)
	}
	if n := len(f.tr.Entries("c1")); n != 2 {
		t.Fatalf("%d entries, want the entry and one refusal", n)
	}
	// A different author may use the same id: ids are scoped to the author.
	f.write(f.say(alice, "hand-off", bob, "", nil))
	b := f.say(bob, "message", bot, "hi", func(s *agentmessage.PersonStatement) { s.MessageID = w.Statement.MessageID })
	if r := f.write(b); r.State != Committed {
		t.Fatalf("another author's use of the id: %+v", r)
	}
}

func TestAnIDRefusedOrNotKeptReturnsThatResultOnRetry(t *testing.T) {
	f := newFixture(t)
	refused := f.say(bob, "message", bot, "x", nil)
	a := f.write(refused)
	f.app.refuse = true
	nk := f.say(alice, "message", bot, "y", nil)
	b := f.write(nk)
	if a.State != Refused || b.State != NotKept {
		t.Fatalf("setup: %+v %+v", a, b)
	}
	f.app.refuse = false
	for _, c := range []struct {
		w    Write
		want Result
	}{{refused, a}, {nk, b}} {
		got := f.write(c.w)
		if got.EntryID != c.want.EntryID || got.State != c.want.State || !got.Replayed {
			t.Fatalf("retry got %+v, want %+v", got, c.want)
		}
	}
	if f.app.keepCalls != 1 {
		t.Fatal("a retry of a refused or not-kept id reached the app again")
	}
}

// A not-kept entry and a refusal verify offline, beside a committed entry.
func TestAStatementForAnotherIdentityAgentIsRefused(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "hello", func(s *agentmessage.PersonStatement) { s.Agent = "EOTHERAGENT" })
	if _, err := f.tr.Write(context.Background(), w); err == nil {
		t.Fatal("a statement for another Identity Agent's conversation c1 was accepted")
	}
	if len(f.tr.Entries("c1")) != 0 || f.app.keepCalls != 0 {
		t.Fatal("it left a trace or reached the app")
	}
}

// chainOf opens every entry of the conversation's chain with the Identity
// Agent's keys and checks each follows the one before: the one chain that
// conversationbundle.Verify reads, not a record of the trail's own.
func (f *fixture) chainOf(conv string) []agentmessage.Record {
	f.t.Helper()
	did, err := f.keys.DID()
	if err != nil {
		f.t.Fatal(err)
	}
	var recs []agentmessage.Record
	prev := ""
	for i, e := range f.tr.Chain(conv) {
		rec, err := agentmessage.Open(did, e.Envelope)
		if err != nil {
			f.t.Fatalf("entry %d is not countersigned by the Identity Agent: %v", i+1, err)
		}
		if rec.Seq != i+1 || rec.PrevHash != prev || e.Hash != agentmessage.Hash(e.Envelope) {
			f.t.Fatalf("entry %d does not follow the one before it", i+1)
		}
		prev = e.Hash
		recs = append(recs, rec)
	}
	if prev != f.tr.Head(conv) {
		f.t.Fatal("the head is not the last entry's hash")
	}
	return recs
}

// A person's entries, their refusals and how each ended are all entries of the
// conversation's one chain, beside an AI agent's, and none holds a word.
func TestAPersonsEntriesRefusalsAndOutcomesAreInTheOneChain(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "one-words", nil)) // e1 pending, e2 committed
	f.write(f.say(bob, "message", bot, "two-words", nil))   // e3 refused: not the owner
	f.app.wrongFP = true
	f.write(f.say(alice, "message", bot, "three-words", nil)) // e4 pending, e5 not kept
	f.app.wrongFP = false
	recs := f.chainOf("c1")
	wantKinds := []string{"message", "outcome", "message", "message", "outcome"}
	if len(recs) != len(wantKinds) {
		t.Fatalf("the chain holds %d entries, want %d", len(recs), len(wantKinds))
	}
	for i, k := range wantKinds {
		if recs[i].Kind != k {
			t.Fatalf("entry %d is a %s, want %s", i+1, recs[i].Kind, k)
		}
	}
	if recs[1].Outcome.State != agentmessage.OutcomeCommitted || recs[1].Outcome.Entry != "e1" ||
		recs[4].Outcome.State != agentmessage.OutcomeNotKept || recs[4].Outcome.Entry != "e4" {
		t.Fatalf("the outcomes name the wrong entries: %+v %+v", recs[1].Outcome, recs[4].Outcome)
	}
	if recs[2].Refusal == "" || recs[0].PersonProof == nil || recs[0].MessageID != "e1" {
		t.Fatal("the entries are not a person's statement and a refusal")
	}
	raw, _ := json.Marshal(f.tr.Chain("c1"))
	for _, w := range []string{"one-words", "two-words", "three-words"} {
		if bytes.Contains(raw, []byte(w)) {
			t.Fatalf("%q is in the chain", w)
		}
	}
	for _, r := range recs {
		raw, _ := json.Marshal(r)
		for _, w := range []string{"one-words", "two-words", "three-words"} {
			if bytes.Contains(raw, []byte(w)) {
				t.Fatalf("%q is in a record", w)
			}
		}
	}
	// The states the view reports are the chain's.
	got := []State{}
	for _, e := range f.tr.Entries("c1") {
		got = append(got, e.State())
	}
	if fmt.Sprint(got) != fmt.Sprint([]State{Committed, Refused, NotKept}) {
		t.Fatalf("states %v", got)
	}
}

// An AI agent's entry is countersigned as ADR-047 has it and joins the same
// chain; a person's entry follows it, and an entry that does not follow the
// end of the chain is refused.
func TestAnAIAgentsEntryJoinsTheSameChain(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "hello", nil)) // e1, e2
	agentRec := agentmessage.Record{
		MessageID: "m-agent", Conversation: "c1", Seq: 3, PrevHash: f.tr.Head("c1"), IATime: "2026-11-06T12:00:00Z",
		Kind: agentmessage.KindReply, From: bot, To: agentmessage.Person(alice), InReplyTo: "e1",
		BodyHash: agentmessage.HashBody([]byte("reply")), OpenedBy: agentmessage.Person(alice),
	}
	env, err := agentmessage.Countersign(f.keys, agentRec)
	if err != nil {
		t.Fatal(err)
	}
	entry := agentmessage.Entry{Conversation: "c1", Seq: 3, MessageID: "m-agent", Envelope: env, Hash: agentmessage.Hash(env)}
	if err := f.tr.AppendAgent("c1", entry); err != nil {
		t.Fatal(err)
	}
	if err := f.tr.AppendAgent("c1", entry); err == nil {
		t.Fatal("the same entry was appended twice")
	}
	res := f.write(f.say(alice, "message", bot, "again", nil))
	if res.EntryID != "e4" || res.State != Committed {
		t.Fatalf("got %+v: a person's entry did not follow the AI agent's", res)
	}
	if recs := f.chainOf("c1"); len(recs) != 5 || recs[2].MessageID != "m-agent" {
		t.Fatalf("the chain is %d entries long", len(recs))
	}
	if len(f.tr.Entries("c1")) != 2 {
		t.Fatal("an AI agent's entry is in the view of a person's entries")
	}
}

func TestWhatTheAppDoesNotConfirmIsNotKept(t *testing.T) {
	cases := map[string]struct {
		set    func(a *app)
		reason string
	}{
		"the app refuses":                {func(a *app) { a.refuse = true }, ReasonNotKept},
		"the app confirms another print": {func(a *app) { a.wrongFP = true }, ReasonNoConfirm},
		"the app does not answer":        {func(a *app) { a.hang = true }, ReasonTimeout},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c.set(f.app)
			res := f.write(f.say(alice, "message", bot, "hello", nil))
			if res.State != NotKept || res.Reason != c.reason {
				t.Fatalf("got %+v", res)
			}
			if len(f.tr.Committed("c1")) != 0 {
				t.Fatal("a not-kept entry is delivered")
			}
			if len(f.app.discarded) != 1 {
				t.Fatal("the app was not told to discard")
			}
		})
	}
}

func TestAnEntryLeftPendingExpiresAsNotKept(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "hello", nil)
	e, err := f.tr.add(f.tr.get("c1"), w, "")
	if err != nil {
		t.Fatal(err)
	}
	f.tr.get("c1").indexAllowed(e)
	if f.tr.ExpirePending(context.Background(), "c1") != 0 {
		t.Fatal("an entry expired inside the timeout")
	}
	f.now = f.now.Add(time.Second)
	if f.tr.ExpirePending(context.Background(), "c1") != 1 || f.tr.Entries("c1")[0].State() != NotKept {
		t.Fatal("a stale pending entry was not marked not kept")
	}
	if len(f.tr.Committed("c1")) != 0 {
		t.Fatal("it is delivered")
	}
}

func TestAnUnprovenAuthorLeavesNoEntry(t *testing.T) {
	f := newFixture(t)
	good := f.say(alice, "message", bot, "hello", nil)

	badSig := good
	badSig.Signature = f.say(bob, "message", bot, "x", nil).Signature

	wrongKey := f.say(alice, "message", bot, "hello", nil)
	f.roster.keys[alice] = "someone-else"

	v0 := good
	v0.Statement.FingerprintVersion = agentmessage.FingerprintV0

	for name, w := range map[string]Write{"a signature that is not the key's": badSig, "a key that does not speak for the person": wrongKey, "an unsalted fingerprint": v0} {
		if _, err := f.tr.Write(context.Background(), w); err == nil {
			t.Fatalf("%s was accepted", name)
		} else if _, ok := err.(*Rejected); !ok {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if len(f.tr.Entries("c1")) != 0 || f.app.keepCalls != 0 {
		t.Fatal("an attempt that proves no author left a trace or reached the app")
	}
}

func TestOwnershipFollowsCommittedHandOffsOnly(t *testing.T) {
	f := newFixture(t)
	f.app.refuse = true
	if r := f.write(f.say(alice, "hand-off", bob, "", nil)); r.State != NotKept {
		t.Fatalf("got %+v", r)
	}
	if o, _ := f.tr.Owner("c1"); o != alice {
		t.Fatalf("a hand-off the app did not keep changed the owner to %s", o)
	}
	f.app.refuse = false
	if r := f.write(f.say(alice, "hand-off", bob, "", nil)); r.State != Committed {
		t.Fatalf("got %+v", r)
	}
	if o, _ := f.tr.Owner("c1"); o != bob {
		t.Fatalf("owner is %s", o)
	}
	// The former owner has lost the write; the new owner has it.
	if r := f.write(f.say(alice, "message", bot, "x", nil)); r.State != Refused || r.Reason != ReasonNotOwner {
		t.Fatalf("former owner: %+v", r)
	}
	if r := f.write(f.say(bob, "message", bot, "x", nil)); r.State != Committed {
		t.Fatalf("new owner: %+v", r)
	}
	if h := f.tr.HandOffs("c1"); len(h) != 1 || h[0].By != alice || h[0].To != bob {
		t.Fatalf("hand-offs: %+v", h)
	}
}

func TestHandOffAndSplitOwnersPassOneCheck(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "one", nil))
	for _, kind := range []string{"split", "hand-off"} {
		edit := func(s *agentmessage.PersonStatement) {
			if kind == "split" {
				s.RangeFirst, s.RangeLast = "e1", "e1"
			}
		}
		// Neither an agent the person may not use nor a non-employee.
		for _, to := range []string{bot2, "ESTRANGER"} {
			if r := f.write(f.say(alice, kind, to, "", edit)); r.State != Refused {
				t.Fatalf("%s to %s: %+v", kind, to, r)
			}
		}
		if kind == "split" {
			if r := f.write(f.say(alice, kind, bob, "", func(s *agentmessage.PersonStatement) { s.RangeFirst, s.RangeLast = "e1", "e9" })); r.State != Refused {
				t.Fatalf("a range of entries that are not there: %+v", r)
			}
		}
		// An agent the person may use, and an active employee.
		r := f.write(f.say(alice, kind, bot, "", edit))
		if r.State != Committed {
			t.Fatalf("%s to an agent: %+v", kind, r)
		}
		// A split does not change the owner of the parent; a hand-off does.
		want := alice
		if kind == "hand-off" {
			want = bot
		}
		if o, _ := f.tr.Owner("c1"); o != want {
			t.Fatalf("after a %s the owner is %s, want %s", kind, o, want)
		}
	}
}

func TestOnlyTheOwnerClosesAndReopens(t *testing.T) {
	f := newFixture(t)
	if r := f.write(f.say(bob, "close", "", "", nil)); r.State != Refused {
		t.Fatalf("a non-owner closed it: %+v", r)
	}
	if r := f.write(f.say(alice, "reopen", "", "", nil)); r.State != Refused {
		t.Fatalf("reopened what is open: %+v", r)
	}
	if r := f.write(f.say(alice, "close", "", "", nil)); r.State != Committed || !f.tr.Closed("c1") {
		t.Fatalf("close: %+v", r)
	}
	if r := f.write(f.say(alice, "message", bot, "x", nil)); r.State != Refused || r.Reason != ReasonClosed {
		t.Fatalf("wrote in a closed conversation: %+v", r)
	}
	if r := f.write(f.say(alice, "reopen", "", "", nil)); r.State != Committed || f.tr.Closed("c1") {
		t.Fatalf("reopen: %+v", r)
	}
}

func TestASignerMayHandOnAConversationItDoesNotOwn(t *testing.T) {
	f := newFixture(t)
	if r := f.write(f.say(boss, "hand-off", bob, "", nil)); r.State != Committed {
		t.Fatalf("%+v", r)
	}
	if h := f.tr.HandOffs("c1"); h[0].By != boss || h[0].From != alice {
		t.Fatalf("%+v", h)
	}
}

func TestANonceIsUsedOnce(t *testing.T) {
	f := newFixture(t)
	first := f.say(alice, "message", bot, "one", nil)
	f.write(first)
	replay := f.say(alice, "message", bot, "two", func(s *agentmessage.PersonStatement) { s.Nonce = first.Statement.Nonce })
	if r := f.write(replay); r.State != Refused || r.Reason != ReasonNonceUsed {
		t.Fatalf("%+v", r)
	}
}

func TestAPrivateAgentsEntryKeepsItsCiphertextHash(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "sealed-bytes", nil)
	w.Private = true
	f.write(w)
	e := f.tr.Entries("c1")[0]
	if e.CiphertextHash != w.Statement.Fingerprint {
		t.Fatal("the ciphertext hash is not kept")
	}
	if recs := f.chainOf("c1"); recs[0].CiphertextHash != w.Statement.Fingerprint || recs[0].CheckSenderProof() != nil {
		t.Fatal("the chain's record does not keep the ciphertext hash")
	}
}

func TestConcurrentRetriesOfOneIDAreKeptOnce(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "hello", nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = f.tr.Write(context.Background(), w) }()
	}
	wg.Wait()
	if f.app.keepCalls != 1 || len(f.tr.Entries("c1")) != 1 {
		t.Fatalf("kept %d times, %d entries", f.app.keepCalls, len(f.tr.Entries("c1")))
	}
}

// Read is the app answering a read: everything it holds, in entry order,
// whatever range was asked, since the trail checks the answer and not the app.
func (a *app) Read(_ context.Context, _, _, _ string) ([]Stored, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down {
		return nil, ErrUnreachable
	}
	var out []Stored
	for i := 1; i <= len(a.kept)+len(a.extra)+8; i++ {
		id := EntryID(i)
		if f, ok := a.kept[id]; ok {
			out = append(out, Stored{EntryID: id, Salt: f.Salt, Words: f.Words})
		} else if s, ok := a.extra[id]; ok {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fixture) read(person string) ([]Passed, error) {
	return f.tr.Read(context.Background(), person, "c1", "", "")
}

func TestARangeWhoseWordsDoNotHashToTheTrailIsRefused(t *testing.T) {
	f := newFixture(t)
	var gov []Governance
	f.tr.record = func(g Governance) { gov = append(gov, g) }
	f.write(f.say(alice, "message", bot, "one", nil))
	f.write(f.say(alice, "message", bot, "two", nil))
	if got, err := f.read(alice); err != nil || len(got) != 2 || string(got[1].Words) != "two" {
		t.Fatalf("an honest read failed: %v %v", got, err)
	}
	for name, tamper := range map[string]func(){
		"changed words": func() { k := f.app.kept["e3"]; k.Words = []byte("TWO"); f.app.kept["e3"] = k },
		"changed salt": func() {
			k := f.app.kept["e3"]
			k.Salt = bytes.Repeat([]byte{9}, agentmessage.MinSalt)
			f.app.kept["e3"] = k
		},
		"a gap": func() { delete(f.app.kept, "e3") },
		"an unknown entry": func() {
			f.app.extra = map[string]Stored{"e9": {EntryID: "e9", Words: []byte("x"), Salt: bytes.Repeat([]byte{1}, agentmessage.MinSalt)}}
		},
	} {
		saved := map[string]Forward{}
		for k, v := range f.app.kept {
			saved[k] = v
		}
		tamper()
		got, err := f.read(alice)
		if err == nil || got != nil || err.Error() != ReasonMismatch {
			t.Fatalf("%s: passed on %v, %v", name, got, err)
		}
		if g := gov[len(gov)-1]; g.Outcome != ReadMismatch || g.Person != alice || g.Conversation != "c1" {
			t.Fatalf("%s: governance %+v", name, g)
		}
		f.app.kept, f.app.extra = saved, nil
	}
}

func TestAReadWhileAnEntryIsPendingPassesOnlyCommittedEntriesAndLogsNoMismatch(t *testing.T) {
	f := newFixture(t)
	var gov []Governance
	f.tr.record = func(g Governance) { gov = append(gov, g) }
	f.write(f.say(alice, "message", bot, "one", nil))
	// A second entry the app has already stored but not yet confirmed.
	w := f.say(alice, "message", bot, "two", nil)
	c := f.tr.get("c1")
	e, err := f.tr.add(c, w, "")
	if err != nil {
		t.Fatal(err)
	}
	c.indexAllowed(e)
	f.app.kept[e.ID] = Forward{Salt: w.Salt, Words: w.Words}
	got, err := f.read(alice)
	if err != nil || len(got) != 1 || got[0].Entry.ID != "e1" || string(got[0].Words) != "one" {
		t.Fatalf("got %v, %v", got, err)
	}
	if g := gov[len(gov)-1]; g.Outcome != ReadPassed || g.Dropped != 1 || g.Passed != 1 {
		t.Fatalf("governance %+v", g)
	}
	// A not-kept entry's words are dropped the same way.
	f.now = f.now.Add(time.Second)
	f.tr.ExpirePending(context.Background(), "c1")
	if got, err := f.read(alice); err != nil || len(got) != 1 {
		t.Fatalf("after expiry: %v %v", got, err)
	}
	for _, g := range gov {
		if g.Outcome == ReadMismatch {
			t.Fatalf("a mismatch was logged: %+v", g)
		}
	}
}

func TestAPrivateAgentsEntryIsCheckedByItsCiphertextHash(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "sealed-bytes", nil)
	w.Private = true
	f.write(w)
	if got, err := f.read(alice); err != nil || len(got) != 1 || got[0].Entry.CiphertextHash == "" {
		t.Fatalf("a private entry was not passed on: %v %v", got, err)
	}
	k := f.app.kept["e1"]
	k.Words = []byte("sealed-bytez")
	f.app.kept["e1"] = k
	if _, err := f.read(alice); err == nil || err.Error() != ReasonMismatch {
		t.Fatalf("altered ciphertext passed: %v", err)
	}
	// The kept ciphertext_hash is the fingerprint of the ciphertext.
	e := f.tr.get("c1").entries[0]
	if e.CiphertextHash != e.Statement.Fingerprint {
		t.Fatal("ciphertext_hash is not the fingerprint of the ciphertext")
	}
}

func TestOnlyThoseInAConversationMayReadIt(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "one", nil))
	if _, err := f.read(bob); err == nil || err.Error() != ReasonMayNotRead {
		t.Fatalf("a stranger read it: %v", err)
	}
	if _, err := f.read(boss); err != nil {
		t.Fatalf("a signer was refused: %v", err)
	}
	if _, err := f.tr.Read(context.Background(), alice, "c1", "e9", ""); err == nil {
		t.Fatal("a range outside the conversation was served")
	}
}

func TestAnAgentIsAddressedOnlyWhenItsGrantAndTheTurnStartersReachBothAllow(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "one", nil))
	// bot's reply answers e1; its onward ask to bot2 uses alice's reach.
	if ok, _ := f.tr.MayAddress("c1", "e1", bot2); ok {
		t.Fatal("alice has no reach to bot2")
	}
	f.roster.reach[alice+"\n"+bot2] = true
	if ok, err := f.tr.MayAddress("c1", "e1", bot2); !ok || err != nil {
		t.Fatalf("both allow: %v %v", ok, err)
	}
	f.roster.noGrant[alice+"\n"+bot2] = true
	if ok, _ := f.tr.MayAddress("c1", "e1", bot2); ok {
		t.Fatal("the agent's own grant refuses, yet it was addressed")
	}
	if r := f.write(f.say(alice, "message", bot2, "hi", nil)); r.State != Refused {
		t.Fatalf("a write to an agent whose grant refuses: %v", r)
	}
}

// The open core names no product, and a refusal uses up its message id: a
// message refused only because the app was unreachable is resent under a new
// id (ADR-068).
func TestAnUnreachableRefusalNamesNoProductAndUsesUpItsID(t *testing.T) {
	if strings.Contains(ReasonUnreachable, "AI Chat") {
		t.Fatalf("the reason names a product: %q", ReasonUnreachable)
	}
	f := newFixture(t)
	f.app.down = true
	w := f.say(alice, "message", bot, "hello", nil)
	if r := f.write(w); r.State != Refused || r.Reason != ReasonUnreachable {
		t.Fatalf("got %+v", r)
	}
	f.app.down = false
	if r := f.write(w); r.State != Refused || !r.Replayed {
		t.Fatalf("the same id, once the app was back, got %+v: it must return the same refusal", r)
	}
	if r := f.write(f.say(alice, "message", bot, "hello", nil)); r.State != Committed {
		t.Fatalf("the message under a new id got %+v", r)
	}
}

// CheckAuthor is the one check that a statement is its author's: Write runs it
// first, and a caller that admits words before they reach Write runs the same.
func TestCheckAuthorIsWhatWriteRunsFirst(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, agentmessage.PersonKindMessage, bot, "hello", nil)
	if err := CheckAuthor(w, testAgent, f.roster); err != nil {
		t.Fatalf("an honest statement was refused: %v", err)
	}
	if err := CheckAuthor(w, "EOTHER", f.roster); err == nil {
		t.Fatal("a statement for another Identity Agent was admitted")
	}
	f.roster.keys[alice] = "EOTHERKEY"
	err := CheckAuthor(w, testAgent, f.roster)
	var rej *Rejected
	if !errors.As(err, &rej) {
		t.Fatalf("a key that does not speak for the person = %v", err)
	}
	if _, werr := f.tr.Write(context.Background(), w); !errors.As(werr, &rej) {
		t.Fatalf("Write admitted what CheckAuthor refused: %v", werr)
	}
	if err := CheckFresh(w.Statement, f.now.Add(6*time.Minute)); err == nil {
		t.Fatal("a statement six minutes old was fresh")
	}
}
