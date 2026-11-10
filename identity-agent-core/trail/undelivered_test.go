package trail

import (
	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/limits"
	"identity-agent-core/mediation"
)

func queuedFor(t *testing.T, f *fixture, path string, entry string) (*mediation.Queue, time.Time) {
	t.Helper()
	l := limits.Defaults()
	q, err := mediation.Open(path, l, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(mediation.Message{ID: QueueID("c1", entry), Conversation: "c1", Sender: alice, Recipient: bot, Sealed: []byte("sealed")}); err != nil {
		t.Fatal(err)
	}
	return q, f.now.Add(l.QueueMaxAge)
}

// A message held for its whole age is refused back, its entry is marked not
// delivered (and stays kept), its sealed copy is deleted from disk, and a second
// pass tells nobody again.
func TestAnExpiredMessageMarksItsEntryNotDeliveredEndToEnd(t *testing.T) {
	f := newFixture(t)
	r := f.write(f.say(alice, "message", bot, "hello", nil))
	path := filepath.Join(t.TempDir(), "q.json")
	q, due := queuedFor(t, f, path, r.EntryID)

	if got, err := f.tr.RefuseExpired(q); err != nil || len(got) != 0 {
		t.Fatalf("before its age: %v %v", got, err)
	}
	f.now = due
	chain := len(f.tr.Chain("c1"))
	got, err := f.tr.RefuseExpired(q)
	if err != nil || len(got) != 1 || got[0].Sender != alice || got[0].Reason != mediation.ReasonExpired {
		t.Fatalf("%+v %v", got, err)
	}
	es := f.tr.Entries("c1")
	if es[0].State() != Committed || es[0].NotDelivered == nil || es[0].NotDelivered.Reason != mediation.ReasonExpired {
		t.Fatalf("the entry was not marked: %+v", es[0])
	}
	if len(f.tr.Chain("c1")) != chain+1 {
		t.Fatal("the mark is not one countersigned outcome")
	}
	if again, _ := mediation.Open(path, limits.Defaults(), nil); again.Len() != 0 {
		t.Fatal("the sealed copy is still on disk")
	}
	if got, err := f.tr.RefuseExpired(q); err != nil || len(got) != 0 || len(f.tr.Chain("c1")) != chain+1 {
		t.Fatalf("told or marked twice: %v %v", got, err)
	}
}

// A queue that cannot be saved keeps the copy; once it can, the entry (already
// marked) is not marked again and the sender is told once.
func TestAnExpiredMessageWhoseDeletionFailsIsToldOnce(t *testing.T) {
	f := newFixture(t)
	r := f.write(f.say(alice, "message", bot, "hello", nil))
	dir := filepath.Join(t.TempDir(), "d")
	os.Mkdir(dir, 0o700)
	path := filepath.Join(dir, "q.json")
	q, due := queuedFor(t, f, path, r.EntryID)
	f.now = due
	os.RemoveAll(dir)
	if got, err := f.tr.RefuseExpired(q); err == nil || len(got) != 0 {
		t.Fatalf("a failed save was reported as done: %v %v", got, err)
	}
	if q.Len() != 1 {
		t.Fatal("the copy went though it could not be saved")
	}
	chain := len(f.tr.Chain("c1"))
	os.Mkdir(dir, 0o700)
	got, err := f.tr.RefuseExpired(q)
	if err != nil || len(got) != 1 || len(f.tr.Chain("c1")) != chain {
		t.Fatalf("%v %v chain %d want %d", got, err, len(f.tr.Chain("c1")), chain)
	}
}

// A message whose entry was never kept is not deleted ahead of the record.
func TestAnExpiredMessageWhoseEntryIsNotKeptStaysHeld(t *testing.T) {
	f := newFixture(t)
	f.app.refuse = true
	nk := f.write(f.say(alice, "message", bot, "x", nil))
	q, due := queuedFor(t, f, "", nk.EntryID)
	f.now = due
	got, err := f.tr.RefuseExpired(q)
	if err == nil || len(got) != 0 || q.Len() != 1 {
		t.Fatalf("%v %v %d", got, err, q.Len())
	}
}

// A conversation this trail does not keep is refused, not treated as marked:
// the message is another record's to mark, so its copy stays held.
func TestAMessageForAConversationThisTrailDoesNotKeepIsLeftHeld(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "hello", nil))
	if err := f.tr.markNotDeliveredIfNot("elsewhere", "e1", mediation.ReasonExpired); err == nil {
		t.Fatal("an unknown conversation was reported as marked")
	}
	q, _ := queuedFor(t, f, filepath.Join(t.TempDir(), "q.json"), "e1")
	if err := q.Enqueue(mediation.Message{ID: QueueID("elsewhere", "e1"), Conversation: "elsewhere", Sender: alice, Recipient: bot, Sealed: []byte("s")}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(limits.Defaults().QueueMaxAge)
	got, err := f.tr.RefuseExpired(q, QueueID("elsewhere", "e1"))
	if err == nil || len(got) != 0 || len(q.Held(bot)) == 0 {
		t.Fatalf("%v %v", got, err)
	}
	for _, m := range q.Held(bot) {
		if m.Conversation == "elsewhere" {
			return
		}
	}
	t.Fatal("the unowned copy was deleted")
}

// An AI agent's entry is marked not delivered too, once, in the chain; an entry
// the chain does not hold has nothing to mark.
func TestAnAgentsExpiredEntryIsMarkedOnceInTheChain(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "hello", nil))
	if err := f.tr.AppendAgent("c1", f.agentEntry(1)); err != nil {
		t.Fatal(err)
	}
	id := EntryID(len(f.tr.Chain("c1")))
	n := len(f.tr.Chain("c1"))
	for range 2 {
		if err := f.tr.markNotDeliveredIfNot("c1", id, mediation.ReasonExpired); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.tr.Chain("c1")); got != n+1 {
		t.Fatalf("the chain grew by %d, want 1", got-n)
	}
	if err := f.tr.markNotDeliveredIfNot("c1", "e99", mediation.ReasonExpired); err != nil || len(f.tr.Chain("c1")) != n+1 {
		t.Fatalf("an entry that is not there was marked: %v", err)
	}
}

// A trail rebuilt from the record that holds the chain takes the not-delivered
// mark back in as the Identity Agent's own note, so the entry is not marked a
// second time and later entries still follow it. Any other entry that carries
// an outcome is still refused.
func TestARebuiltTrailTakesTheNotDeliveredMarkBackIn(t *testing.T) {
	f := newFixture(t)
	if err := f.tr.AppendAgent("c1", f.agentEntry(1)); err != nil {
		t.Fatal(err)
	}
	if err := f.tr.markNotDeliveredIfNot("c1", "e1", mediation.ReasonExpired); err != nil {
		t.Fatal(err)
	}
	chain := f.tr.Chain("c1")
	if len(chain) != 2 {
		t.Fatalf("setup: chain of %d", len(chain))
	}

	again := New(f.roster, f.app, Options{Agent: testAgent, Now: func() time.Time { return f.now },
		Countersign: func(r agentmessage.Record) (*didcomm.Envelope, error) { return agentmessage.Countersign(f.keys, r) }})
	if err := again.Open("c1", alice, true); err != nil {
		t.Fatal(err)
	}
	for _, e := range chain {
		if err := again.AppendAgent("c1", e); err != nil {
			t.Fatalf("entry %d of the record was not taken back in: %v", e.Seq, err)
		}
	}
	if err := again.markNotDeliveredIfNot("c1", "e1", mediation.ReasonExpired); err != nil || len(again.Chain("c1")) != 2 {
		t.Fatalf("the entry was marked a second time: %v, chain %d", err, len(again.Chain("c1")))
	}
	if err := again.AppendAgent("c1", f.agentEntryOn(again, 2)); err != nil {
		t.Fatalf("an entry after the mark did not follow it: %v", err)
	}

	// Another party's outcome is not taken in this way.
	other := agentmessage.Record{
		MessageID: "x1", Conversation: "c1", Seq: 4, PrevHash: again.Head("c1"), IATime: "2026-11-06T12:00:00Z",
		Kind: agentmessage.KindOutcome, From: "ESOMEONEELSE", InReplyTo: "e1", BodyHash: agentmessage.HashBody(nil),
		Outcome: &agentmessage.Outcome{Entry: "e1", State: agentmessage.OutcomeNotDelivered, Reason: "x"}, OpenedBy: agentmessage.Person(alice),
	}
	env, err := agentmessage.Countersign(f.keys, other)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.AppendAgent("c1", agentmessage.Entry{Conversation: "c1", Seq: 4, MessageID: "x1", Envelope: env, Hash: agentmessage.Hash(env)}); err == nil {
		t.Fatal("an outcome from another sender was appended")
	}
}

// agentEntryOn is agentEntry for the end of another trail's chain.
func (f *fixture) agentEntryOn(tr *Trail, i int) agentmessage.Entry {
	f.t.Helper()
	seq := len(tr.Chain("c1")) + 1
	rec := agentmessage.Record{
		MessageID: "b" + time.Duration(i).String(), Conversation: "c1", Seq: seq, PrevHash: tr.Head("c1"),
		IATime: "2026-11-06T12:00:00Z", Kind: agentmessage.KindReply, From: bot, To: agentmessage.Person(alice),
		InReplyTo: "e1", BodyHash: agentmessage.HashBody([]byte("r")), OpenedBy: agentmessage.Person(alice),
	}
	env, err := agentmessage.Countersign(f.keys, rec)
	if err != nil {
		f.t.Fatal(err)
	}
	return agentmessage.Entry{Conversation: "c1", Seq: seq, MessageID: rec.MessageID, Envelope: env, Hash: agentmessage.Hash(env)}
}
