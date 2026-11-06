package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/recovery"
)

// theMapOf is the root map the core keeps, as it is on disk.
func theMapOf(t *testing.T, b *brokenGlass) *recovery.RootAIDMap {
	t.Helper()
	m, err := recovery.LoadRootAIDMap(b.s.DataDir)
	if err != nil || len(m.Entries) != 1 {
		t.Fatalf("root map %+v %v", m, err)
	}
	return m
}

func restart(b *brokenGlass) {
	b.s.witnessing.witnessMu.Lock()
	b.s.witnessing.witnessJobs = nil
	b.s.witnessing.movedOnTries = nil
	b.s.witnessing.movedOnEnded = nil
	b.s.witnessing.witnessMu.Unlock()
}

// An entry an older version wrote, when break-glass was ungated and signed
// nothing, names a root whose log is not sent to witnesses; the one the signed
// rotation wrote is.
func TestAnOldFormatRootMapEntryIsNotWitnessed(t *testing.T) {
	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	eventually(t, "the old root's founding reaches its witness", func() bool { return w.holds(b.oldAID) == 1 })
	w.setDown(true)
	if code, out := b.rotate(t); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	time.Sleep(300 * time.Millisecond)

	// The entry as it was written before 746602a8: nothing signed.
	m := theMapOf(t, b)
	signed := m.Entries[0]
	m.Entries[0].AuthorizationSignatures = nil
	writeMap(t, b, m)
	restart(b)

	w.setDown(false)
	for i := 0; i < 3; i++ {
		b.s.witnessOwnLog()
		time.Sleep(100 * time.Millisecond)
	}
	if got := w.holds(b.oldAID); got != 1 {
		t.Fatalf("an old-format entry had the old root's log sent: the witness holds %d events of it", got)
	}

	m.Entries[0] = signed
	writeMap(t, b, m)
	b.s.witnessOwnLog()
	eventually(t, "the signed entry's old root is witnessed", func() bool { return w.holds(b.oldAID) == 2 })
}

func writeMap(t *testing.T, b *brokenGlass, m *recovery.RootAIDMap) {
	t.Helper()
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.s.DataDir, "root_aid_map.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Once the witnesses hold the rotation the old root's job ends: the entry says
// so, no job is left, and the witness is not asked again.
func TestTheJobForAFinishedRootEnds(t *testing.T) {
	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	eventually(t, "the old root's founding reaches its witness", func() bool { return w.holds(b.oldAID) == 1 })
	if code, out := b.rotate(t); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	eventually(t, "the witness holds the rotation", func() bool { return w.holds(b.oldAID) == 2 })
	eventually(t, "the entry says the old root is witnessed", func() bool {
		m, err := recovery.LoadRootAIDMap(b.s.DataDir)
		return err == nil && len(m.Entries) == 1 && m.Entries[0].WitnessedAt != ""
	})
	b.s.witnessing.witnessMu.Lock()
	_, still := b.s.witnessing.witnessJobs[b.oldAID]
	b.s.witnessing.witnessMu.Unlock()
	if still {
		t.Fatal("the job for the old root is still there")
	}
	for i := 0; i < 3; i++ {
		b.s.witnessOwnLog()
		time.Sleep(100 * time.Millisecond)
	}
	if got := w.holds(b.oldAID); got != 2 {
		t.Fatalf("the old root's log changed at the witness: %d", got)
	}
}

// A pass that read the root map while the old root was still open, and is
// overtaken by the end of that root's witnessing before it adds the job, does
// not add it.
func TestAPassThatReadTheRootBeforeItEndedDoesNotAddItsJob(t *testing.T) {
	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	eventually(t, "the old root's founding reaches its witness", func() bool { return w.holds(b.oldAID) == 1 })
	if code, out := b.rotate(t); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	eventually(t, "the entry says the old root is witnessed", func() bool {
		m, err := recovery.LoadRootAIDMap(b.s.DataDir)
		return err == nil && len(m.Entries) == 1 && m.Entries[0].WitnessedAt != ""
	})
	// Open the entry again as it was when the pass read it.
	m := theMapOf(t, b)
	entry := m.Entries[0]
	m.Entries[0].WitnessedAt = ""
	writeMap(t, b, m)
	restart(b)

	b.s.witnessing.witnessMu.Lock()
	b.s.witnessing.afterMovedOnRead = func() { b.s.endMovedOn(entry, false) }
	b.s.witnessing.witnessMu.Unlock()
	keeper := b.s.KeriDriver.(drivers.KELKeeper)
	b.s.witnessRootsMovedOn(keeper)

	b.s.witnessing.witnessMu.Lock()
	_, still := b.s.witnessing.witnessJobs[b.oldAID]
	b.s.witnessing.witnessMu.Unlock()
	if still {
		t.Fatal("a finished root's job was added back")
	}
}

// A witness that never answers is not contacted for ever: tries get further
// apart, and after a bound the core gives up and writes that down.
func TestAWitnessThatNeverHoldsTheRotationIsGivenUpOn(t *testing.T) {
	old := [3]any{movedOnBackoff, movedOnLongestBackoff, movedOnGiveUpAfter}
	movedOnBackoff, movedOnLongestBackoff, movedOnGiveUpAfter = 0, 0, 3
	defer func() {
		movedOnBackoff, movedOnLongestBackoff, movedOnGiveUpAfter = old[0].(time.Duration), old[1].(time.Duration), old[2].(int)
	}()

	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	eventually(t, "the old root's founding reaches its witness", func() bool { return w.holds(b.oldAID) == 1 })
	w.setDown(true)
	if code, out := b.rotate(t); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	eventually(t, "the core gives up on the old root's witness", func() bool {
		b.s.witnessOwnLog()
		m, err := recovery.LoadRootAIDMap(b.s.DataDir)
		return err == nil && len(m.Entries) == 1 && m.Entries[0].WitnessingGaveUpAt != ""
	})
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 3; i++ {
		b.s.witnessOwnLog()
		time.Sleep(100 * time.Millisecond)
	}
	b.s.witnessing.witnessMu.Lock()
	_, still := b.s.witnessing.witnessJobs[b.oldAID]
	b.s.witnessing.witnessMu.Unlock()
	if still {
		t.Fatal("a job for the old root remains after giving up")
	}
}
