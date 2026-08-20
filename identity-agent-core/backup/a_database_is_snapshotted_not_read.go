package backup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
	SweepUpAbandoned(dir)

	// VACUUM INTO refuses to overwrite, so this must be a path that does not
	// exist yet rather than a created temp file.
	tmp, err := os.MkdirTemp(dir, snapshotPrefix)
	if err != nil {
		return nil, fmt.Errorf("make room for the snapshot: %w", err)
	}
	inUse(tmp)
	defer func() {
		noLongerInUse(tmp)
		os.RemoveAll(tmp)
	}()
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

// The working directories both sides of a backup unpack into. Each sweeps
// BOTH, because a directory is only ever cleaned by the next run of whatever
// made it — and a crashed restore's copy would otherwise survive every backup
// forever, since most people never run a second restore.
const (
	snapshotPrefix  = ".snapshot-"
	restoringPrefix = ".restoring-"
)

// RestoringPrefix is the working directory prefix the restore side uses.
const RestoringPrefix = restoringPrefix

var (
	workingDirs   = map[string]bool{}
	workingDirsMu sync.Mutex
)

// InUse marks a working directory as belonging to a run that is still going.
func InUse(dir string) { inUse(dir) }

// NoLongerInUse releases a working directory marked by InUse.
func NoLongerInUse(dir string) { noLongerInUse(dir) }

func inUse(dir string) {
	workingDirsMu.Lock()
	workingDirs[dir] = true
	workingDirsMu.Unlock()
}

func noLongerInUse(dir string) {
	workingDirsMu.Lock()
	delete(workingDirs, dir)
	workingDirsMu.Unlock()
}

func isInUse(dir string) bool {
	workingDirsMu.Lock()
	defer workingDirsMu.Unlock()
	return workingDirs[dir]
}

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
// Called at the start of each run rather than only at the end, because the run
// that could have cleaned up is precisely the one that died.
//
// A directory this process is still using is never taken, and that check is
// what makes this safe rather than the age below. A directory's mtime moves
// when entries are added or removed, NOT when a file inside it is written — so
// a snapshot directory ages from the moment VACUUM INTO created the file in
// it, however long the vacuum then runs. Ageing alone would delete the working
// directory of a live backup of a large database, which is the failure this
// used to have.
func SweepUpAbandoned(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() ||
			(!strings.HasPrefix(name, snapshotPrefix) && !strings.HasPrefix(name, restoringPrefix)) {
			continue
		}
		full := filepath.Join(dir, name)
		if isInUse(full) {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < abandonedAfter {
			continue
		}
		os.RemoveAll(full)
	}
}

// abandonedAfter is how long a working directory left by ANOTHER process must
// have sat untouched before it is treated as abandoned. Directories belonging
// to this process are known exactly and are not subject to it.
const abandonedAfter = time.Hour
