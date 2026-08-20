package backup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// sqliteMagic opens every SQLite file, as the first 16 bytes of the header.
const sqliteMagic = "SQLite format 3\x00"

// LooksLikeADatabase reports whether a file is a SQLite database.
//
// By its header rather than its name. Naming the databases is the allow list
// this package exists to be rid of — .db, .sqlite, .sqlite3 and no extension
// at all are used across this data directory, and the next one to be added
// will be whatever its author felt like. The header is the thing SQLite itself
// checks.
func LooksLikeADatabase(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	header := make([]byte, len(sqliteMagic))
	if n, err := f.Read(header); err != nil || n < len(sqliteMagic) {
		return false
	}
	return string(header) == sqliteMagic
}

// snapshotAnotherDatabase takes a consistent copy of a database this package
// does not own.
//
// The reason this exists rather than a registry every new database must
// remember to join: a registry is an allow list wearing a different hat. It
// fails exactly the way naming files failed — somebody adds a database, nobody
// registers it, every backup succeeds, and the gap surfaces on the day of the
// restore. There are already four databases in a running agent's data
// directory (the identity store, the sandbox, the organisation store and the
// AI memory) and only the first was ever handled.
//
// Reading one as bytes is what produced the fault this whole change began
// with: they run in write-ahead-log mode, so the file on disk is missing every
// transaction since the last checkpoint, and the archive is valid and empty.
// A second connection sees the log, so a snapshot taken through one is
// complete — proven against a live database with an uncheckpointed write in
// it.
//
// Opened read-only. This is somebody else's database and a backup must not be
// able to change it.
func snapshotAnotherDatabase(path, workDir string) ([]byte, error) {
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open %s to copy it: %w", filepath.Base(path), err)
	}
	defer db.Close()

	// VACUUM INTO will not overwrite, so this has to be a path that does not
	// exist yet.
	tmp, err := os.MkdirTemp(workDir, snapshotPrefix)
	if err != nil {
		return nil, fmt.Errorf("make room to copy %s: %w", filepath.Base(path), err)
	}
	inUse(tmp)
	defer func() {
		noLongerInUse(tmp)
		os.RemoveAll(tmp)
	}()

	out := filepath.Join(tmp, "copy.db")
	if _, err := db.Exec("VACUUM INTO ?", out); err != nil {
		return nil, fmt.Errorf("copy %s: %w", filepath.Base(path), err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("read the copy of %s back: %w", filepath.Base(path), err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("the copy of %s came out empty", filepath.Base(path))
	}
	return data, nil
}
