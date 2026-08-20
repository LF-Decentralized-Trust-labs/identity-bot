package backup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
)

// SnapshotSQLite writes a complete, consistent copy of a live database.
//
// Reading identity.db with os.ReadFile does not do this, and the way it fails
// is the worst kind. The database runs in WAL mode, so a committed transaction
// lands in identity.db-wal and only reaches identity.db at a checkpoint —
// which SQLite does on its own schedule and typically not for some time. The
// sweep deliberately excludes -wal and -shm, correctly, because they are
// meaningless without the database they belong to. So a plain read takes the
// main file alone: every transaction since the last checkpoint is missing, and
// on a young database that is all of them.
//
// Nothing downstream could notice. Verification compares the archive against
// what was collected, and an incomplete database round-trips through
// encryption and digesting perfectly. The archive is valid, its manifest is
// honest, every check passes, and the database inside it is empty.
//
// VACUUM INTO takes the snapshot through SQLite itself: it reads in a
// transaction, so it sees the WAL contents and any concurrent writer is
// serialised against it rather than tearing the copy in half. What comes out
// is a single self-contained file with no sidecars — which is exactly what a
// restore needs, since it has nowhere to put a -wal anyway.
func SnapshotSQLite(db *sql.DB, dir string) ([]byte, error) {
	if db == nil {
		return nil, fmt.Errorf("no database to snapshot")
	}

	// VACUUM INTO refuses to overwrite, so this must be a path that does not
	// exist yet rather than a created temp file.
	tmp, err := os.MkdirTemp(dir, ".snapshot-")
	if err != nil {
		return nil, fmt.Errorf("make room for the snapshot: %w", err)
	}
	defer os.RemoveAll(tmp)
	path := filepath.Join(tmp, "identity.db")

	if _, err := db.Exec("VACUUM INTO ?", path); err != nil {
		return nil, fmt.Errorf("snapshot the database: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the snapshot back: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("the snapshot came out empty")
	}
	return data, nil
}
