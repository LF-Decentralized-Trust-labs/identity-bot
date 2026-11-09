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

// A backup server and a local folder choose by name too, so the same rule reads
// the names they use.
func TestTheNameCheckReadsTheNamesAFolderAndABackupServerUse(t *testing.T) {
	for _, name := range []string{
		"/home/me/Backups/backup-full-20261107-090000.iab",
		`C:\Backups\backup-delta-20261107-090000.iab`,
		"20261107-090000.iab",
		"20261107-090000-1.iab",
	} {
		w := ArchiveFreshnessWarnings("2026-08-13T12:00:00Z", name, time.Time{})
		if len(w) != 1 || !strings.Contains(w[0], "renamed") {
			t.Fatalf("%s: a name claiming a later time went unremarked: %v", name, w)
		}
		if w := ArchiveFreshnessWarnings("2026-11-07T09:00:00Z", name, time.Time{}); len(w) != 0 {
			t.Fatalf("%s: a truthful name was warned about: %v", name, w)
		}
	}
}
