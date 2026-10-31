package backup

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"identity-agent-core/sqlitedb"
)

// liveDatabase opens a database at path the way a running store does, in WAL
// mode, holding rows, with its last write still in the log beside it.
func liveDatabase(t *testing.T, path string, rows ...string) *sql.DB {
	t.Helper()
	db, err := sqlitedb.Open(path, sqlitedb.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS notes (body TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO notes (body) VALUES (?)`, r); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// snapshotOf is a database holding rows, as an archive carries it.
func snapshotOf(t *testing.T, rows ...string) []byte {
	t.Helper()
	dir := t.TempDir()
	db := liveDatabase(t, filepath.Join(dir, "source.db"), rows...)
	data, err := snapshotAnotherDatabase(filepath.Join(dir, "source.db"), dir)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func notesIn(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT body FROM notes`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sound(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var verdict string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&verdict); err != nil || verdict != "ok" {
		t.Fatalf("the database is not sound: %q (%v)", verdict, err)
	}
}

// A database restored while it is open, as an add-on's store is while the
// Identity Agent runs, is restored into: the connection already open sees the
// restored rows, a write through it afterwards is kept, and the database
// opened afresh is sound and holds both.
func TestADatabaseRestoredWhileOpenIsRestoredInto(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai-memory.db")
	open := liveDatabase(t, path, "written before the restore")
	defer open.Close()
	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Fatalf("the test needs a live log beside the database: %v", err)
	}

	if err := RestoreFile(dir, "ai-memory.db", snapshotOf(t, "from the archive", "also from the archive")); err != nil {
		t.Fatal(err)
	}

	if got := notesIn(t, open); len(got) != 2 || got[0] != "also from the archive" || got[1] != "from the archive" {
		t.Fatalf("the open connection sees %v, not the restored rows", got)
	}
	if _, err := open.Exec(`INSERT INTO notes (body) VALUES ('written after the restore')`); err != nil {
		t.Fatalf("the open connection cannot write after the restore: %v", err)
	}
	open.Close()

	sound(t, path)
	again, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if got := notesIn(t, again); len(got) != 3 {
		t.Fatalf("opened afresh the database holds %v", got)
	}
}

// A database restored to a path where none is, but where a log left by one
// that was removed still lies, is not handed that log: SQLite would apply it
// to the restored file.
func TestAnOrphanLogIsNotAppliedToARestoredDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	old := liveDatabase(t, path, "the old database")
	// Copy its live log aside, close it, remove the database, and put the
	// log back as a crash or a removal would leave it.
	wal, err := os.ReadFile(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	os.Remove(path)
	os.Remove(path + "-shm")
	if err := os.WriteFile(path+"-wal", wal, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RestoreFile(dir, "store.db", snapshotOf(t, "from the archive")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("the orphan log is still beside the restored database: %v", err)
	}
	sound(t, path)
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	if got := notesIn(t, db); len(got) != 1 || got[0] != "from the archive" {
		t.Fatalf("the restored database holds %v", got)
	}
}

// A database whose pages are another size than the backed-up copy's is still
// restored into: a database in WAL mode takes a backup only of its own size.
func TestADatabaseOfAnotherPageSizeIsRestoredInto(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA page_size = 8192; CREATE TABLE notes (body TEXT); PRAGMA journal_mode = WAL`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	open := liveDatabase(t, path, "written before the restore")
	defer open.Close()

	if err := RestoreFile(dir, "store.db", snapshotOf(t, "from the archive")); err != nil {
		t.Fatal(err)
	}
	if got := notesIn(t, open); len(got) != 1 || got[0] != "from the archive" {
		t.Fatalf("the open connection sees %v", got)
	}
	open.Close()
	sound(t, path)
}

// Anything that is not a database is written as a file, replacing what was
// there whole.
func TestAFileThatIsNotADatabaseIsWritten(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreFile(dir, "sub/settings.json", []byte(`{"new":true}`)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "sub", "settings.json")); string(b) != `{"new":true}` {
		t.Fatalf("read back %q", b)
	}
}

// A destination that is not a usable database, which is when somebody
// restores, is replaced as a file, its log removed with it.
func TestADamagedDatabaseIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.WriteFile(p, []byte("this is not a database at all, it is garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RestoreFile(dir, "store.db", snapshotOf(t, "from the archive")); err != nil {
		t.Fatalf("a damaged database could not be restored: %v", err)
	}
	sound(t, path)
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	if got := notesIn(t, db); len(got) != 1 || got[0] != "from the archive" {
		t.Fatalf("the restored database holds %v", got)
	}
}
