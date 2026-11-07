package trail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
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
}

func (r *roster) KeySpeaksFor(person, signer, _ string) bool { return r.keys[person] == signer }
func (r *roster) IsAIAgent(id string) bool                   { return r.agents[id] }
func (r *roster) MayUseAgent(p, a string) bool               { return r.reach[p+"\n"+a] }
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
	}
	for i, p := range []string{alice, bob, boss} {
		id, _, _ := agentbody.Identity(signerOf(byte(i + 1)))
		f.roster.keys[p] = id
	}
	f.tr = New(f.roster, f.app, Options{Agent: testAgent, ForwardTimeout: 50 * time.Millisecond, Now: func() time.Time { return f.now }})
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
			if rep := Verify(es); !rep.Verified {
				t.Fatalf("a refusal does not verify offline: %v", rep.Faults)
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

func TestAnExportedTrailNamingTwoIdentityAgentsOrAnUnsaltedEntryAfterASaltedOneFails(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "one", nil))
	f.write(f.say(alice, "message", bot, "two", nil))
	raw, _ := json.Marshal(f.tr.Entries("c1"))
	es, _ := Read(raw)
	if r := Verify(es); !r.Verified {
		t.Fatalf("a good trail failed: %v", r.Faults)
	}
	other := append([]Entry(nil), es...)
	other[1].Statement.Agent = "EOTHERAGENT"
	if Verify(other).Verified {
		t.Fatal("a trail naming two Identity Agents verified")
	}
	late := append([]Entry(nil), es...)
	late[1].Statement.FingerprintVersion = agentmessage.FingerprintV0
	r := Verify(late)
	if r.Verified || !strings.Contains(strings.Join(r.Faults, "\n"), "after a salted one") {
		t.Fatalf("an unsalted entry after a salted one was not named: %v", r.Faults)
	}
}

func TestANotKeptEntryAndARefusalVerifyOffline(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "one", nil)) // committed
	f.write(f.say(bob, "message", bot, "two", nil))   // refused: not the owner
	f.app.wrongFP = true
	nk := f.write(f.say(alice, "message", bot, "three", nil)) // not kept
	f.app.wrongFP = false
	if nk.State != NotKept || nk.Reason != ReasonNoConfirm {
		t.Fatalf("got %+v", nk)
	}
	if len(f.app.discarded) != 1 || f.app.discarded[0] != nk.EntryID {
		t.Fatalf("the app was not told to discard: %v", f.app.discarded)
	}
	f.write(f.say(alice, "message", bot, "four", nil)) // committed

	raw, _ := json.Marshal(f.tr.Entries("c1"))
	es, err := Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	rep := Verify(es)
	if !rep.Verified || rep.Head != f.tr.Head("c1") {
		t.Fatalf("does not verify: %v", rep.Faults)
	}
	states := []State{Committed, Refused, NotKept, Committed}
	for i, e := range es {
		if e.State() != states[i] {
			t.Fatalf("entry %d is %s, want %s", i+1, e.State(), states[i])
		}
	}

	// Each kind of tampering is caught without the app.
	for name, change := range map[string]func(es []Entry){
		"a refusal's reason rewritten":       func(es []Entry) { es[1].Refusal = "no reason" },
		"a not-kept entry's signature":       func(es []Entry) { es[2].Signature = es[0].Signature },
		"a not-kept entry's fingerprint":     func(es []Entry) { es[2].Statement.Fingerprint = es[0].Statement.Fingerprint },
		"an entry removed":                   func(es []Entry) { es[2] = es[3] },
		"a refusal turned into an entry":     func(es []Entry) { es[1].Refusal = "" },
		"a not-kept entry made to have none": func(es []Entry) { es[2].Outcome.Reason = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := copyEntries(es)
			change(c)
			if Verify(c).Verified {
				t.Fatal("tampering went unnoticed")
			}
		})
	}
	// A trail cut short still verifies as far as it goes, but its head is not
	// the recorded one, which is what the key history catches.
	if short := Verify(es[:3]); short.Head == f.tr.Head("c1") {
		t.Fatal("a cut trail has the head of the whole")
	}
}

func TestWordsAreCheckedAgainstTheTrailOffline(t *testing.T) {
	f := newFixture(t)
	w := f.say(alice, "message", bot, "one", nil)
	f.write(w)
	f.write(f.say(bob, "message", bot, "refused words", nil))
	es := f.tr.Entries("c1")
	good := map[string]Kept{"e1": {Salt: w.Salt, Words: w.Words}}
	if r := VerifyWords(es, good); !r.Verified {
		t.Fatalf("%v", r.Faults)
	}
	if r := VerifyWords(es, map[string]Kept{"e1": {Salt: w.Salt, Words: []byte("changed")}}); r.Verified {
		t.Fatal("changed words verified")
	}
	if r := VerifyWords(es, nil); r.Verified {
		t.Fatal("a committed entry with no words verified")
	}
	good["e2"] = Kept{Salt: w.Salt, Words: []byte("refused words")}
	if r := VerifyWords(es, good); r.Verified {
		t.Fatal("words for a refusal verified")
	}
}

func TestReadRefusesAFieldCarryingWords(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "one", nil))
	raw, _ := json.Marshal(f.tr.Entries("c1"))
	bad := strings.Replace(string(raw), `"seq":1`, `"seq":1,"words":"hello"`, 1)
	if _, err := Read([]byte(bad)); err == nil {
		t.Fatal("a trail with a words field was read")
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
	e := f.tr.append(f.tr.get("c1"), w, "")
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
	if !Verify(f.tr.Entries("c1")).Verified {
		t.Fatal("does not verify")
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
