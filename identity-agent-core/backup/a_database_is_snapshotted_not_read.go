package backup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	// Anything left behind by a run that died before its cleanup.
	//
	// What is in here is an unencrypted copy of the most sensitive store on
	// the device, so it must not be allowed to accumulate — and it would
	// otherwise be invisible, because the sweep skips anything named
	// identity.db as already captured and so never reports it either.
	SweepUpAbandoned(dir, snapshotPrefix)

	// VACUUM INTO refuses to overwrite, so this must be a path that does not
	// exist yet rather than a created temp file.
	tmp, err := os.MkdirTemp(dir, snapshotPrefix)
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

// snapshotPrefix names the working directory a snapshot is taken in.
const snapshotPrefix = ".snapshot-"

// SweepUpAbandoned removes working directories left by a run that did not
// finish.
//
// Both the snapshot side and the restore side unpack a plaintext copy of the
// identity database into the data directory and remove it on the way out. A
// crash, a kill or a power loss between those two points leaves that copy on
// disk with nothing that will ever clean it up, and the file sweep skips it —
// it matches on basename, sees identity.db, and records it as already
// captured — so it is not reported as skipped either. An unencrypted
// duplicate of the whole identity store then sits there indefinitely and
// nothing says so.
//
// Called at the start of each run rather than only at the end, because the
// run that could have cleaned up is precisely the one that died.
func SweepUpAbandoned(dir, prefix string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}
