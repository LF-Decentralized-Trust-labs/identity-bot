package mediation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/limits"
)

// A message the sender was told was queued is still queued after a restart,
// with its place in the shares, and what was delivered or kept stays so.
func TestTheQueueSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.json")
	clk := &clock{t: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	q, err := Open(path, small(), clk.now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := q.Enqueue(msg(i, "c", "s", 100)); err != nil {
			t.Fatal(err)
		}
		clk.t = clk.t.Add(time.Hour)
	}
	if err := q.Delivered("m1"); err != nil {
		t.Fatal(err)
	}
	if err := q.Discard("m3"); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path, small(), clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 2 || r.Bytes() != 200 {
		t.Fatalf("after a restart: %d messages, %d bytes", r.Len(), r.Bytes())
	}
	if h := r.Held("r"); len(h) != 1 || h[0].ID != "m2" || len(h[0].Sealed) != 100 {
		t.Fatalf("the recipient is offered %+v", h)
	}
	// m1 was delivered before the restart, so being kept now deletes it.
	if err := r.Kept("m1"); err != nil || r.Len() != 1 {
		t.Fatalf("delivered-then-kept after a restart left %d held (%v)", r.Len(), err)
	}
	// The shares were rebuilt: a duplicate id is still refused, and a third restart agrees.
	var ref *Refusal
	if err := r.Enqueue(msg(2, "c", "s", 1)); !errors.As(err, &ref) || ref.Reason != ReasonDuplicate {
		t.Fatalf("got %v", err)
	}
	if again, err := Open(path, small(), clk.now); err != nil || again.Len() != 1 {
		t.Fatalf("%v %v", again, err)
	}
}

// A message that outlived its age while the process was down is refused back
// when the queue is next expired, with its age counted from when it was queued.
func TestAMessageKeepsItsAgeAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.json")
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	clk := &clock{t: start}
	q, _ := Open(path, small(), clk.now)
	if err := q.Enqueue(msg(1, "c", "s", 10)); err != nil {
		t.Fatal(err)
	}
	clk.t = start.Add(small().QueueMaxAge + time.Minute)
	r, err := Open(path, small(), clk.now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Expire()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "m1" || got[0].Reason != ReasonExpired {
		t.Fatalf("got %+v", got)
	}
	if again, _ := Open(path, small(), clk.now); again.Len() != 0 {
		t.Fatal("an expired message came back after another restart")
	}
}

// A queue file that cannot be read is an error and is left as it is, never an
// empty queue, which would drop accepted messages without a word.
func TestADamagedQueueFileIsNotReplacedByAnEmptyQueue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"messages":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if q, err := Open(path, small(), nil); err == nil || q != nil {
		t.Fatalf("a damaged file opened: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != `{"version":1,"messages":[` {
		t.Fatal("the damaged file was changed")
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"messages":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, small(), nil); err == nil {
		t.Fatal("a newer version was read as this one")
	}
}

// A message that cannot be written down is refused, so none is ever accepted
// that a restart would lose, and the queue is as it was.
func TestAMessageThatCannotBeSavedIsRefused(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(filepath.Join(dir, "gone", "q.json"), small(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var ref *Refusal
	if err := q.Enqueue(msg(1, "c", "s", 10)); !errors.As(err, &ref) || ref.Reason != ReasonNotSaved {
		t.Fatalf("got %v", err)
	}
	if q.Len() != 0 || q.Bytes() != 0 {
		t.Fatalf("a refused message is held: %d %d", q.Len(), q.Bytes())
	}
}

// The file holds sealed bytes only, and is private to the Identity Agent.
func TestTheQueueFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.json")
	q, _ := Open(path, small(), nil)
	if err := q.Enqueue(msg(1, "c", "s", 10)); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("%v %v", fi, err)
	}
}

// A queue whose file can no longer be written, with one message held and its
// clock past the message's age.
func unwritableQueue(t *testing.T) (*Queue, string, func()) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "q.json")
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	clk := &clock{t: start}
	q, err := Open(path, small(), clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(msg(1, "c", "s", 10)); err != nil {
		t.Fatal(err)
	}
	clk.t = start.Add(small().QueueMaxAge + time.Minute)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	return q, path, func() {}
}

// If the queue cannot be saved, a change is not made: memory still agrees with
// the disk, so a crash cannot bring back a message that memory had dropped, and
// a sender is not told twice.
func TestAFailedSaveLeavesDiscardMarkAndExpireUnmade(t *testing.T) {
	for name, change := range map[string]func(*Queue) error{
		"discard":   func(q *Queue) error { return q.Discard("m1") },
		"delivered": func(q *Queue) error { return q.Delivered("m1") },
		"expire":    func(q *Queue) error { _, err := q.Expire(); return err },
	} {
		t.Run(name, func(t *testing.T) {
			q, _, _ := unwritableQueue(t)
			if err := change(q); err == nil {
				t.Fatal("a change that could not be saved was reported as made")
			}
			if q.Len() != 1 || q.Bytes() != 10 {
				t.Fatalf("memory changed though the save failed: %d held, %d bytes", q.Len(), q.Bytes())
			}
			if got := q.Held("r"); len(got) != 1 {
				t.Fatalf("the message is no longer waiting: %v", got)
			}
			if due := q.Due(); len(due) != 1 {
				t.Fatalf("the message is not still due: %v", due)
			}
		})
	}
	// The mark that completes a message (delivered and kept) must not delete it
	// while the disk still has it.
	q, _, _ := unwritableQueue(t)
	if err := q.Kept("m1"); err == nil {
		t.Fatal("not saved but reported made")
	}
	if err := q.Delivered("m1"); err == nil || q.Len() != 1 {
		t.Fatalf("a mark that could not be saved changed the queue: %v %d", err, q.Len())
	}
}

// A failed Expire is retried and tells each sender once.
func TestExpireTellsEachSenderOnceAcrossAFailedSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.json")
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	clk := &clock{t: start}
	q, _ := Open(path, small(), clk.now)
	q.Enqueue(msg(1, "c", "s", 10))
	clk.t = start.Add(small().QueueMaxAge)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil { // a directory where the file goes: the write fails
		t.Fatal(err)
	}
	if got, err := q.Expire(); err == nil || len(got) != 0 {
		t.Fatalf("expired with no save: %v %v", got, err)
	}
	os.Remove(path)
	first, err := q.Expire()
	if err != nil || len(first) != 1 {
		t.Fatalf("%v %v", first, err)
	}
	if second, _ := q.Expire(); len(second) != 0 {
		t.Fatalf("told twice: %v", second)
	}
}

// A part-filled Limits takes the defaults for the rest, at the queue's own entry
// points: it must not refuse every message.
func TestAQueueMadeWithPartFilledLimitsTakesTheDefaults(t *testing.T) {
	dir := t.TempDir()
	for name, mk := range map[string]func() *Queue{
		"New": func() *Queue { return New(limits.Limits{QueueMessages: 5}, nil) },
		"Open": func() *Queue {
			q, _ := Open(filepath.Join(dir, "q.json"), limits.Limits{QueueMessages: 5}, nil)
			return q
		},
		"zero": func() *Queue { return New(limits.Limits{}, nil) },
	} {
		q := mk()
		if err := q.Enqueue(msg(1, "c", "s", 10)); err != nil {
			t.Fatalf("%s: a part-filled limit refused a message: %v", name, err)
		}
		if due, _ := q.Expire(); len(due) != 0 {
			t.Fatalf("%s: a queue with no age expired a new message", name)
		}
	}
}

// A mark that could not be saved is not made, so a later mark that can be saved
// does not complete a message on the strength of the one that was not: kept
// (not saved) then delivered (saved) leaves the message held, because it was
// only delivered.
func TestAMarkThatCouldNotBeSavedIsNotCountedWhenTheNextOneIs(t *testing.T) {
	for name, order := range map[string][2]func(*Queue, string) error{
		"kept then delivered": {(*Queue).Kept, (*Queue).Delivered},
		"delivered then kept": {(*Queue).Delivered, (*Queue).Kept},
	} {
		t.Run(name, func(t *testing.T) {
			q, path, _ := unwritableQueue(t)
			if err := order[0](q, "m1"); err == nil {
				t.Fatal("not saved but reported made")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := order[1](q, "m1"); err != nil {
				t.Fatal(err)
			}
			if q.Len() != 1 || q.Bytes() != 10 {
				t.Fatalf("the unsaved mark was counted: %d held", q.Len())
			}
		})
	}
}
