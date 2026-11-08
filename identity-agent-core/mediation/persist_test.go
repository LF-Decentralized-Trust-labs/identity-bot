package mediation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	got := r.Expire()
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
