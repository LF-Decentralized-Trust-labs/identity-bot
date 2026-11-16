package activitylog_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"identity-agent-core/activitylog"
	"identity-agent-core/activitylog/activitylogtest"
	"identity-agent-core/sqlitedb"
)

// Before 2026-11-15 the activity log was the data directory's sandbox.db. A data
// directory that has only that file opens as the log, under its new name,
// with every signed row still verifying, and nothing is left under the old one.
func TestALogKeptAsSandboxDBIsAdoptedUnderItsNewName(t *testing.T) {
	dir := t.TempDir()
	ts := activitylogtest.NewSigner(t)

	l, err := activitylog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, cap := range []string{"a.one", "a.two", "a.three"} {
		appendChained(t, l, ts, cap)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// As an older build left it.
	if err := os.Rename(filepath.Join(dir, activitylog.FileName), filepath.Join(dir, activitylog.LegacyFileName)); err != nil {
		t.Fatal(err)
	}

	l, err = activitylog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if broken, why, err := verifyFirst(l, ts.Keys, nil); err != nil || broken != 0 {
		t.Fatalf("the adopted log does not verify: broken=%d (%s) err=%v", broken, why, err)
	}
	if h, err := l.LastEventHash(); err != nil || h == "" {
		t.Fatalf("the adopted log holds none of its rows: %q %v", h, err)
	}
	if _, err := os.Stat(filepath.Join(dir, activitylog.LegacyFileName)); err == nil {
		t.Error("sandbox.db is still there beside activity.db")
	}
	if filepath.Base(l.Path()) != "activity.db" {
		t.Errorf("the log is at %s", l.Path())
	}
}

// When both files are there, activity.db is the log and sandbox.db is left alone.
func TestActivityDBWinsWhenBothAreThere(t *testing.T) {
	dir := t.TempDir()
	l, err := activitylog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := os.WriteFile(filepath.Join(dir, activitylog.LegacyFileName), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err = activitylog.Open(dir)
	if err != nil {
		t.Fatalf("an old file beside the log stopped it opening: %v", err)
	}
	l.Close()
	if b, _ := os.ReadFile(filepath.Join(dir, activitylog.LegacyFileName)); string(b) != "not a database" {
		t.Error("sandbox.db was touched")
	}
}

// A write-ahead log left at activity.db's name with no activity.db belongs to
// no database the adoption knows. It is removed before sandbox.db is renamed,
// so SQLite never applies another database's pages to the adopted log.
func TestAStaleLogAtTheNewNameIsNotAppliedToTheAdoptedLog(t *testing.T) {
	other := t.TempDir()
	o, err := sqlitedb.Open(filepath.Join(other, activitylog.FileName), sqlitedb.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	o.SetMaxOpenConns(1)
	if _, err := o.Exec(`CREATE TABLE intruder (x TEXT); INSERT INTO intruder VALUES ('from another database')`); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.ReadFile(filepath.Join(other, activitylog.FileName+"-wal"))
	if err != nil || len(foreign) == 0 {
		t.Fatalf("no write-ahead log to plant: %d bytes, %v", len(foreign), err)
	}
	o.Close()

	dir := t.TempDir()
	l, err := activitylog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	// As a downgrade that renamed only the database file back leaves it.
	if err := os.Rename(filepath.Join(dir, activitylog.FileName), filepath.Join(dir, activitylog.LegacyFileName)); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, activitylog.FileName+"-shm"))
	if err := os.WriteFile(filepath.Join(dir, activitylog.FileName+"-wal"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}

	l, err = activitylog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var intruder, logTable int
	l.DB().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'intruder'`).Scan(&intruder)
	l.DB().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'invocation_log'`).Scan(&logTable)
	var verdict string
	if err := l.DB().QueryRow("PRAGMA quick_check").Scan(&verdict); err != nil {
		t.Fatal(err)
	}
	if intruder != 0 || logTable != 1 || verdict != "ok" {
		t.Errorf("another database's log was applied: intruder=%d invocation_log=%d quick_check=%q", intruder, logTable, verdict)
	}
}

// A sandbox.db whose newest rows are still only in its write-ahead log, as a
// build that stopped without closing it leaves it, is adopted with those rows:
// the log is folded into the file before the file is renamed, and nothing is
// left under the old name.
func TestRowsStillInTheOldLogsWriteAheadLogAreAdopted(t *testing.T) {
	dir := t.TempDir()
	ts := activitylogtest.NewSigner(t)
	l, err := activitylog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, cap := range []string{"a.one", "a.two", "a.three"} {
		appendChained(t, l, ts, cap)
	}
	want, err := l.LastEventHash()
	if err != nil || want == "" {
		t.Fatalf("no last hash: %q %v", want, err)
	}

	// Copied while still open, as a stop without a close leaves the files.
	crashed := t.TempDir()
	for _, f := range []struct{ from, to string }{
		{activitylog.FileName, activitylog.LegacyFileName},
		{activitylog.FileName + "-wal", activitylog.LegacyFileName + "-wal"},
	} {
		b, err := os.ReadFile(filepath.Join(dir, f.from))
		if err != nil {
			t.Fatal(err)
		}
		if f.to == activitylog.LegacyFileName+"-wal" && len(b) == 0 {
			t.Fatal("the write-ahead log is empty, so this proves nothing")
		}
		if err := os.WriteFile(filepath.Join(crashed, f.to), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	l, err = activitylog.Open(crashed)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if got, err := l.LastEventHash(); err != nil || got != want {
		t.Errorf("the adopted log ends at %q (%v), want %q", got, err, want)
	}
	if broken, why, err := verifyFirst(l, ts.Keys, nil); err != nil || broken != 0 {
		t.Errorf("the adopted log does not verify: broken=%d (%s) err=%v", broken, why, err)
	}
	for _, name := range []string{activitylog.LegacyFileName, activitylog.LegacyFileName + "-wal", activitylog.LegacyFileName + "-shm"} {
		if _, err := os.Stat(filepath.Join(crashed, name)); err == nil {
			t.Errorf("%s is still there after the adoption", name)
		}
	}
}

// An existence check that fails for any reason but "not there" stops the
// adoption, so it never renames over an activity.db it could not see.
func TestACheckThatCannotLookStopsTheAdoption(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not stop a lookup on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory it has no permission for")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "data")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, activitylog.LegacyFileName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	if err := activitylog.AdoptTheLegacyName(dir); err == nil {
		t.Error("a directory it could not look in read as holding no activity.db")
	}
}
