package backup

import (
	"strings"
	"testing"
	"time"
)

func TestAnArchiveOlderThanOneTheDeviceHasSeenIsWarnedAbout(t *testing.T) {
	seen := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	w := ArchiveFreshnessWarnings("2026-08-13T12:00:00Z", "E1/backup-full-20260813-120005.iab", seen)
	if len(w) != 1 || !strings.Contains(w[0], "not the newest") {
		t.Fatalf("an older archive must be warned about: %v", w)
	}
	// The newest this device made is not warned about, though its history is
	// stamped a few seconds after the archive was built.
	if w := ArchiveFreshnessWarnings("2026-11-01T11:59:55Z", "E1/backup-full-20261101-120000.iab", seen); len(w) != 0 {
		t.Fatalf("the device's own newest archive was warned about: %v", w)
	}
	// A new machine has seen nothing and has nothing to compare with.
	if w := ArchiveFreshnessWarnings("2026-08-13T12:00:00Z", "E1/backup-full-20260813-120005.iab", time.Time{}); len(w) != 0 {
		t.Fatalf("%v", w)
	}
}

func TestAnOldArchiveRenamedToLookNewestIsCaughtByItsOwnTime(t *testing.T) {
	// Uploaded under a name that sorts last, which is what makes it "latest".
	w := ArchiveFreshnessWarnings("2026-08-13T12:00:00Z", "E1/backup-full-20261107-090000.iab", time.Time{})
	if len(w) != 1 || !strings.Contains(w[0], "renamed") {
		t.Fatalf("a name that claims a time the archive does not must be called out: %v", w)
	}
}

func TestTheNewestArchiveSeenSurvivesAndOnlyMovesForward(t *testing.T) {
	cs := NewConfigStore(t.TempDir())
	if !cs.NewestArchiveSeen().IsZero() {
		t.Fatal("a new machine has seen nothing")
	}
	cs.NoteArchiveSeen("2026-11-01T12:00:00Z")
	cs.NoteArchiveSeen("2026-08-13T12:00:00Z")
	if got := cs.NewestArchiveSeen(); got.Format(time.RFC3339) != "2026-11-01T12:00:00Z" {
		t.Fatalf("an older archive moved the mark back: %v", got)
	}
}
