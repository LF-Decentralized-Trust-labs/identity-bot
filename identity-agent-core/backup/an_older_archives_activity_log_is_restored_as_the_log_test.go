package backup

import (
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/activitylog"
)

// restoreAll writes every file FilesToRestore says an archive's sections
// restore to, in its order, as a recovery does, and returns what it left out.
func restoreAll(t *testing.T, dir string, sections map[string][]byte) []SkippedFile {
	t.Helper()
	files, left, err := FilesToRestore(sections)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := RestoreFile(dir, f.Rel, f.Raw); err != nil {
			t.Fatal(err)
		}
	}
	return left
}

// An archive an older build wrote carries the activity log as sandbox.db. It is
// restored as activity.db, the log's own name: into a log already there it
// replaces its contents, and into a directory with none it becomes the log.
func TestAnOlderArchivesActivityLogIsRestoredAsTheLog(t *testing.T) {
	older := map[string][]byte{FileSectionPrefix + "sandbox.db": snapshotOf(t, "from the archive")}

	// Nothing there yet.
	dir := t.TempDir()
	if left := restoreAll(t, dir, older); len(left) != 0 {
		t.Errorf("left out %v", left)
	}
	if _, err := os.Stat(filepath.Join(dir, activitylog.LegacyFileName)); err == nil {
		t.Error("sandbox.db was written beside the log")
	}
	db := liveDatabase(t, filepath.Join(dir, activitylog.FileName))
	defer db.Close()
	if got := notesIn(t, db); len(got) != 1 || got[0] != "from the archive" {
		t.Errorf("activity.db holds %v", got)
	}

	// A log already there is restored into.
	dir = t.TempDir()
	live := liveDatabase(t, filepath.Join(dir, activitylog.FileName), "newer")
	defer live.Close()
	restoreAll(t, dir, older)
	if got := notesIn(t, live); len(got) != 1 || got[0] != "from the archive" {
		t.Errorf("the log holds %v after the restore", got)
	}
}

// A data directory can hold a stale sandbox.db beside activity.db: an older
// build run after a downgrade makes a new one, and the upgrade again leaves it
// there. The backup never carries it, and an archive that carries both (as
// one written before that rule might) restores activity.db and leaves
// sandbox.db out, saying so, so the stale copy is never written over the log.
func TestAStaleSandboxDBNeverReplacesTheLog(t *testing.T) {
	src := t.TempDir()
	live := liveDatabase(t, filepath.Join(src, activitylog.FileName), "the log")
	stale := liveDatabase(t, filepath.Join(src, activitylog.LegacyFileName), "a stale copy")

	c := &Collector{DataDir: src}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	skipped, err := c.collectEveryOtherFile(bundle)
	live.Close()
	stale.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle.Sections[FileSectionPrefix+activitylog.LegacyFileName]; ok {
		t.Error("the backup carried sandbox.db")
	}
	if _, ok := bundle.Sections[FileSectionPrefix+activitylog.FileName]; !ok {
		t.Fatal("the backup did not carry activity.db")
	}
	said := false
	for _, s := range skipped {
		if s.Path == activitylog.LegacyFileName {
			said = true
		}
	}
	if !said {
		t.Error("the backup left sandbox.db out without saying so")
	}

	dir := t.TempDir()
	restoreAll(t, dir, bundle.Sections)
	db := liveDatabase(t, filepath.Join(dir, activitylog.FileName))
	if got := notesIn(t, db); len(got) != 1 || got[0] != "the log" {
		t.Errorf("activity.db holds %v after the restore", got)
	}
	db.Close()

	// The same, from an archive that carries both.
	bundle.Sections[FileSectionPrefix+activitylog.LegacyFileName] = snapshotOf(t, "a stale copy")
	dir = t.TempDir()
	left := restoreAll(t, dir, bundle.Sections)
	db = liveDatabase(t, filepath.Join(dir, activitylog.FileName))
	defer db.Close()
	if got := notesIn(t, db); len(got) != 1 || got[0] != "the log" {
		t.Errorf("activity.db holds %v after restoring an archive with both", got)
	}
	if len(left) != 1 || left[0].Path != activitylog.LegacyFileName || left[0].Reason != TheLogIsCarriedUnderItsOwnName {
		t.Errorf("the restore left out %v", left)
	}
	if _, err := os.Stat(filepath.Join(dir, activitylog.LegacyFileName)); err == nil {
		t.Error("sandbox.db was written beside the log")
	}
}

// RestoreFile alone cannot know what else an archive carries, so it refuses
// sandbox.db rather than guess where it goes.
func TestRestoreFileRefusesTheLogsOldName(t *testing.T) {
	if err := RestoreFile(t.TempDir(), activitylog.LegacyFileName, snapshotOf(t, "x")); err == nil {
		t.Error("RestoreFile wrote sandbox.db")
	}
}

// A sandbox.db with no activity.db beside it is the only copy of the log: its
// rename was refused, for one because the database was busy. The backup
// carries it, and a restore writes it as activity.db.
func TestASandboxDBWithNoLogBesideItIsCarried(t *testing.T) {
	src := t.TempDir()
	only := liveDatabase(t, filepath.Join(src, activitylog.LegacyFileName), "the only copy")
	c := &Collector{DataDir: src}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	_, err := c.collectEveryOtherFile(bundle)
	only.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle.Sections[FileSectionPrefix+activitylog.LegacyFileName]; !ok {
		t.Fatal("the backup left out the only copy of the log")
	}
	dir := t.TempDir()
	restoreAll(t, dir, bundle.Sections)
	db := liveDatabase(t, filepath.Join(dir, activitylog.FileName))
	defer db.Close()
	if got := notesIn(t, db); len(got) != 1 || got[0] != "the only copy" {
		t.Errorf("activity.db holds %v after the restore", got)
	}
}

// Whether an archive carries the log is decided from where its sections
// restore to, not from how they are spelt, so a log named ./activity.db still
// keeps a stale sandbox.db out.
func TestTheLogIsRecognisedByWhereItRestoresTo(t *testing.T) {
	for _, logName := range []string{"./activity.db", "x/../activity.db", "Activity.DB"} {
		sections := map[string][]byte{
			FileSectionPrefix + logName:      snapshotOf(t, "the log"),
			FileSectionPrefix + "sandbox.db": snapshotOf(t, "a stale copy"),
		}
		files, left, err := FilesToRestore(sections)
		if err != nil {
			t.Fatalf("%s: %v", logName, err)
		}
		if len(files) != 1 || len(left) != 1 || left[0].Reason != TheLogIsCarriedUnderItsOwnName {
			t.Errorf("%s: writes %d files, leaves out %v", logName, len(files), left)
		}
	}
}

// Two sections that name one file, however they are spelt, refuse the
// archive: which one was written last would otherwise be decided by chance.
func TestTwoSectionsForOneFileRefuseTheArchive(t *testing.T) {
	for _, pair := range [][2]string{
		{"settings.json", "./settings.json"},
		{"sub/notes.json", "sub/x/../notes.json"},
		{"notes.json", "Notes.JSON"},
	} {
		_, _, err := FilesToRestore(map[string][]byte{
			FileSectionPrefix + pair[0]: []byte("{}"),
			FileSectionPrefix + pair[1]: []byte("{}"),
		})
		if err == nil {
			t.Errorf("an archive naming %q and %q was accepted", pair[0], pair[1])
		}
	}
}

// The file systems of macOS and Windows do not tell case apart, so neither do
// the names a backup leaves out, nor the activity log's old name.
func TestNamesAreComparedWithoutCase(t *testing.T) {
	for _, name := range []string{"Controller_Grants.json", "MCP_TOKENS.json", "SecureEnclave/Machine_Key.sep", "Activity.db-WAL"} {
		if skipReason(name) == "" {
			t.Errorf("%s is carried", name)
		}
		if NotRestored(name) == "" {
			t.Errorf("%s is restored", name)
		}
	}

	files, left, err := FilesToRestore(map[string][]byte{FileSectionPrefix + "Sandbox.DB": snapshotOf(t, "x")})
	if err != nil || len(left) != 0 || len(files) != 1 || files[0].Rel != activitylog.FileName {
		t.Errorf("Sandbox.DB alone restores as %v, leaving out %v (%v)", files, left, err)
	}
	_, left, err = FilesToRestore(map[string][]byte{
		FileSectionPrefix + "SANDBOX.db":  snapshotOf(t, "a stale copy"),
		FileSectionPrefix + "activity.db": snapshotOf(t, "the log"),
	})
	if err != nil || len(left) != 1 || left[0].Reason != TheLogIsCarriedUnderItsOwnName {
		t.Errorf("SANDBOX.db beside the log was not left out: %v (%v)", left, err)
	}
	if err := RestoreFile(t.TempDir(), "Sandbox.db", snapshotOf(t, "x")); err == nil {
		t.Error("RestoreFile wrote Sandbox.db")
	}
}

// A section that names the data directory itself is no file at all.
func TestASectionNamingTheDataDirectoryIsRefused(t *testing.T) {
	for _, name := range []string{".", "./", "sandbox.db/..", "a/.."} {
		if rel, ok := FilePathOfSection(FileSectionPrefix + name); ok {
			t.Errorf("%q resolves to %q", name, rel)
		}
	}
}
