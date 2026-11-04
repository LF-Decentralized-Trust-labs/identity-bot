package server

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"identity-agent-core/recovery"
)

// aClock is a clock a test moves by hand.
type aClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *aClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *aClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func useClock(t *testing.T) *aClock {
	c := &aClock{t: time.Now()}
	old := witnessClock
	witnessClock = c.now
	t.Cleanup(func() { witnessClock = old })
	return c
}

func triesOf(b *brokenGlass) int {
	b.s.witnessing.witnessMu.Lock()
	defer b.s.witnessing.witnessMu.Unlock()
	return b.s.witnessing.movedOnTries[b.oldAID].attempts
}

func gaveUp(b *brokenGlass) bool {
	m, err := recovery.LoadRootAIDMap(b.s.DataDir)
	return err == nil && len(m.Entries) == 1 && m.Entries[0].WitnessingGaveUpAt != ""
}

// settle waits for the worker to finish what it was asked.
func settle(b *brokenGlass) {
	time.Sleep(150 * time.Millisecond)
}

// A rotated-away root whose witness is down, with the clock still.
func downAfterRotation(t *testing.T) (*brokenGlass, *aWitness) {
	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	eventually(t, "the old root's founding reaches its witness", func() bool { return w.holds(b.oldAID) == 1 })
	w.setDown(true)
	if code, out := b.rotate(t); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	return b, w
}

// Passes other work asks for inside the wait are not tries; each try waits as
// long as the backoff says (30s doubling to 1h), and the twelfth gives up.
func TestTriesAreSpacedByTheBackoffAndTheTwelfthGivesUp(t *testing.T) {
	clock := useClock(t)
	b, _ := downAfterRotation(t)
	eventually(t, "the first try is counted", func() bool { b.s.witnessOwnLog(); return triesOf(b) >= 1 })
	settle(b)
	if got := triesOf(b); got != 1 {
		t.Fatalf("tries after the first: %d", got)
	}
	// Many passes inside the wait: none counts.
	for i := 0; i < 50; i++ {
		b.s.witnessOwnLog()
		time.Sleep(5 * time.Millisecond)
	}
	settle(b)
	if got := triesOf(b); got != 1 {
		t.Fatalf("passes inside the wait were counted as tries: %d", got)
	}
	// Just short of 30s: still waiting. Past it: a second try.
	clock.add(29 * time.Second)
	b.s.witnessOwnLog()
	settle(b)
	if got := triesOf(b); got != 1 {
		t.Fatalf("a try came before the wait was over: %d", got)
	}
	clock.add(2 * time.Second)
	b.s.witnessOwnLog()
	eventually(t, "the second try", func() bool { return triesOf(b) == 2 })
	// The wait doubles: 60s now.
	clock.add(59 * time.Second)
	b.s.witnessOwnLog()
	settle(b)
	if got := triesOf(b); got != 2 {
		t.Fatalf("the doubled wait was not kept: %d", got)
	}
	// Spaced tries up to the bound; the clock moves past any wait each time.
	for n := 3; n <= 12; n++ {
		clock.add(2 * time.Hour)
		if gaveUp(b) {
			t.Fatalf("gave up before try %d", n)
		}
		eventually(t, "the next spaced try", func() bool {
			b.s.witnessOwnLog()
			return triesOf(b) == n || gaveUp(b)
		})
	}
	eventually(t, "the give-up after twelve tries", func() bool { return gaveUp(b) })
}

// A restart tries a root it gave up on again.
func TestARestartTriesARootItGaveUpOnAgain(t *testing.T) {
	clock := useClock(t)
	b, w := downAfterRotation(t)
	for n := 1; n <= 12; n++ {
		clock.add(2 * time.Hour)
		eventually(t, "a try", func() bool { b.s.witnessOwnLog(); return gaveUp(b) || triesOf(b) >= n })
	}
	eventually(t, "given up", func() bool { return gaveUp(b) })

	w.setDown(false)
	b.s.witnessOwnLog()
	settle(b)
	if w.holds(b.oldAID) != 1 {
		t.Fatal("a root given up on was sent to without a restart")
	}
	b.s.beginWitnessing()
	if gaveUp(b) {
		t.Fatal("the give-up survived the start")
	}
	b.s.witnessOwnLog()
	eventually(t, "the rotation reaches the old root's witness after the restart", func() bool { return w.holds(b.oldAID) == 2 })
}

// One witness of three gone for good must not count as a failure: the old
// root's threshold holds the rotation.
func TestAnOldRootIsHeldWhenItsThresholdHoldsTheRotation(t *testing.T) {
	clock := useClock(t)
	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	eventually(t, "the old root's founding reaches its witness", func() bool { return w.holds(b.oldAID) == 1 })
	if code, out := b.rotate(t); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	// A try made before the rotation was signed is spaced like any other.
	eventually(t, "the witness holds the rotation", func() bool {
		clock.add(2 * time.Hour)
		b.s.witnessOwnLog()
		return w.holds(b.oldAID) == 2
	})
	eventually(t, "witnessed", func() bool {
		m, err := recovery.LoadRootAIDMap(b.s.DataDir)
		return err == nil && m.Entries[0].WitnessedAt != ""
	})
	// Reopen the job as the old root of three witnesses, two of which are gone
	// and one of which holds the log, with a threshold of one.
	m := theMapOf(t, b)
	m.Entries[0].WitnessedAt = ""
	writeMap(t, b, m)
	b.s.witnessRecord(b.oldAID, "", []string{w.name, "DgoneA", "DgoneB"}, 1)
	clock.add(time.Hour)
	eventually(t, "the entry says the old root is witnessed, not given up", func() bool {
		m, err := recovery.LoadRootAIDMap(b.s.DataDir)
		return err == nil && m.Entries[0].WitnessedAt != ""
	})
	if gaveUp(b) {
		t.Fatal("a threshold that held counted as given up")
	}
}

// The own-log job of an identity no longer kept here is dropped; a moved-on
// root's job stays.
func TestTheJobOfAnIdentityNoLongerKeptHereIsDropped(t *testing.T) {
	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	eventually(t, "founding at witness", func() bool { return w.holds(b.oldAID) == 1 })
	b.s.witnessRecord("EReplacedByARestore", "", []string{w.name}, 1)
	b.s.witnessOwnLog()
	b.s.witnessing.witnessMu.Lock()
	_, stale := b.s.witnessing.witnessJobs["EReplacedByARestore"]
	b.s.witnessing.witnessMu.Unlock()
	if stale {
		t.Fatal("the job of an identity no longer kept here remains")
	}
}
