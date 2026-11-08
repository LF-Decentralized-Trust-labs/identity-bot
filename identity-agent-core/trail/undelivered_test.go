package trail

import (
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
