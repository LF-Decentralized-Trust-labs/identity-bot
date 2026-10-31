package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"identity-agent-core/internal/atomicfile"

	sqlite "modernc.org/sqlite"
)

// RestoreFile puts a file section back at rel under dataDir.
//
// A restore runs while the Identity Agent is running, and some of the files
// it puts back are databases somebody has open right now: the activity log,
// or an add-on's store such as its AI conversations. Writing over one of
// those as a file is wrong three ways. The connections already open keep the
// old file, so they carry on without the restored data and their next writes
// land in a file that is about to be thrown away. The old database's
// write-ahead log is left beside the new file, and SQLite applies it to the
// next connection that opens it, which corrupts it. And on Windows a file
// that is open cannot be replaced at all.
//
// So a database that is already there is restored INTO, through SQLite's own
// online backup, which takes the database's locks, replaces its pages and its
// log together, and is seen by every connection already open on their next
// read. Nothing has to be closed or told, so an add-on needs no part in it.
// A database that is not there yet is written as a file, after removing any
// log left beside the path by one that was removed. Anything else is written
// as a file.
func RestoreFile(dataDir, rel string, raw []byte) error {
	dest := filepath.Join(dataDir, rel)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("make room for %s: %w", rel, err)
	}
	if !isADatabase(raw) {
		if err := atomicfile.Write(dest, raw, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", rel, err)
		}
		return nil
	}
	usable := false
	if _, err := os.Stat(dest); err == nil {
		usable = aUsableDatabase(dest)
	}
	if !usable {
		// Nothing there, or something SQLite cannot use: garbage, or a
		// database that fails its own check. That is exactly when somebody
		// restores, so it is replaced as a file. Its log goes first: no
		// usable database owns it, and SQLite would take it for the restored
		// file's own.
		for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
			if err := os.Remove(dest + sidecar); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove the log left beside %s: %w", rel, err)
			}
		}
		if err := atomicfile.Write(dest, raw, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", rel, err)
		}
		return nil
	}
	if err := restoreIntoDatabase(raw, dest, dataDir); err != nil {
		return fmt.Errorf("restore %s: %w", rel, err)
	}
	return nil
}

// aUsableDatabase reports whether the file at path is a database SQLite can
// open and that passes its quick check. Busy is not unusable: somebody is
// using it, and the restore waits for them.
func aUsableDatabase(path string) bool {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return false
	}
	defer db.Close()
	var verdict string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&verdict); err != nil {
		return isBusy(err)
	}
	return verdict == "ok"
}

// isADatabase reports whether raw is a SQLite database, by its header, as
// LooksLikeADatabase does for a file.
func isADatabase(raw []byte) bool {
	return len(raw) >= len(sqliteMagic) && string(raw[:len(sqliteMagic)]) == sqliteMagic
}

// restoreIntoDatabase replaces the contents of the database at dest with raw,
// through SQLite's online backup, while others may have it open.
func restoreIntoDatabase(raw []byte, dest, workDir string) error {
	tmp, err := os.MkdirTemp(workDir, restoringPrefix)
	if err != nil {
		return fmt.Errorf("make room for the backed-up copy: %w", err)
	}
	inUse(tmp)
	defer func() {
		noLongerInUse(tmp)
		os.RemoveAll(tmp)
	}()
	src := filepath.Join(tmp, "copy.db")
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		return fmt.Errorf("unpack the backed-up copy: %w", err)
	}

	// Only the wait for a busy database, which is what every other
	// connection to it has. Its journal mode is the database's own, and is
	// left as it is.
	db, err := sql.Open("sqlite", dest+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// A database in WAL mode takes a backup only of its own page size, so
	// the copy is rebuilt at that size first when the two differ.
	var pageSize int
	if err := conn.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return fmt.Errorf("read the database's page size: %w", err)
	}
	if err := atPageSize(src, pageSize); err != nil {
		return err
	}

	return conn.Raw(func(driverConn any) error {
		r, ok := driverConn.(interface {
			NewRestore(string) (*sqlite.Backup, error)
		})
		if !ok {
			return fmt.Errorf("this SQLite driver cannot restore into an open database")
		}
		b, err := r.NewRestore(src)
		if err != nil {
			return err
		}
		// Busy is a writer that has the database right now. The backup may
		// be stepped again once it has finished, and the wait is bounded.
		deadline := time.Now().Add(30 * time.Second)
		for {
			more, err := b.Step(-1)
			if err != nil {
				if isBusy(err) && time.Now().Before(deadline) {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				b.Finish()
				return err
			}
			if !more {
				break
			}
		}
		return b.Finish()
	})
}

// atPageSize rebuilds the database at path with pages of size bytes, when it
// has any other size.
func atPageSize(path string, size int) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	var have int
	if err := db.QueryRow("PRAGMA page_size").Scan(&have); err != nil {
		return fmt.Errorf("read the backed-up copy's page size: %w", err)
	}
	if have == size {
		return nil
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA page_size = %d; VACUUM", size)); err != nil {
		return fmt.Errorf("rebuild the backed-up copy at the database's page size: %w", err)
	}
	return nil
}

// isBusy reports whether err is SQLite's SQLITE_BUSY or SQLITE_LOCKED, in
// any of their extended forms.
func isBusy(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Code() & 0xff {
	case 5, 6: // SQLITE_BUSY, SQLITE_LOCKED
		return true
	}
	return false
}
