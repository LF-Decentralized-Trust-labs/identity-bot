// Package activitylog is the Identity Agent's activity log: the signed,
// chained record of who did what, under whose authority, and of the
// governance decisions taken about them. It is part of the core: the Identity
// Agent is the governance layer, and the record is what anybody outside
// checks it against.
//
// The log is kept in the data directory's activity.db, in the invocation_log
// table. It was called sandbox.db until 2026-11-15, and is renamed on first open
// (AdoptTheLegacyName). That database also holds the add-ons' tables, and its
// schema is one versioned sequence of migrations (migrations.go), so this
// package opens the database and applies that whole sequence, and an add-on
// keeps its own tables on the handle it is given.
package activitylog

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"identity-agent-core/sqlitedb"

	_ "modernc.org/sqlite"
)

// Log is the activity log, open on its database.
type Log struct {
	db     *sql.DB
	dbPath string
	// writeMu serialises writes. The log is a hash chain, so two concurrent
	// writers reading the same predecessor would fork it silently.
	writeMu sync.Mutex
	// signerMu guards eventSigner.
	signerMu    sync.RWMutex
	eventSigner EventSigner // nil = events written unsigned (degraded)
}

// Open opens the log kept in dataDir, making the database and bringing its
// schema up to date as needed.
func Open(dataDir string) (*Log, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	if err := AdoptTheLegacyName(dataDir); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, FileName)
	db, err := sqlitedb.Open(dbPath, sqlitedb.Settings{ForeignKeys: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open activity database: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping activity database: %w", err)
	}

	if err := ApplyMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to apply migrations: %w", err)
	}
	return &Log{db: db, dbPath: dbPath}, nil
}

// DB is the database the log is kept in, which the sandboxed-app add-on keeps
// its own tables in too.
func (l *Log) DB() *sql.DB { return l.db }

// Close closes the database.
func (l *Log) Close() error { return l.db.Close() }

// Path is where the database is.
func (l *Log) Path() string { return l.dbPath }

// FileName is the log's database in the data directory.
const FileName = "activity.db"

// LegacyFileName is what the database was called before 2026-11-15. An archive
// written by an older build carries it under this name.
const LegacyFileName = "sandbox.db"

// AdoptTheLegacyName renames a data directory's sandbox.db to activity.db when
// there is no activity.db yet, before anything opens either. It renames and
// does not copy: an older build opening the directory afterwards would find an
// empty sandbox.db, so downgrading means renaming activity.db back first (said
// in the release note). When both exist nothing is touched: activity.db is the
// log.
//
// The database file is renamed alone, after everything SQLite keeps beside it
// has been dealt with:
//   - sandbox.db's own write-ahead log is folded into it first, through SQLite,
//     so the file is the whole log and no row is left in a file that is not
//     renamed with it;
//   - any -wal, -shm or -journal file already sitting at activity.db's name with
//     no activity.db is removed, because SQLite would take it for the renamed
//     database's own and apply another database's pages to the log;
//   - the directory is flushed, so the rename survives a crash.
//
// Each existence check tells "not there" apart from "could not look": a check
// that fails for any other reason stops the adoption rather than reading as
// absent, so the rename never lands over an activity.db that is there.
func AdoptTheLegacyName(dataDir string) error {
	old, now := filepath.Join(dataDir, LegacyFileName), filepath.Join(dataDir, FileName)
	switch _, err := os.Lstat(now); {
	case err == nil:
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("checking for %s: %w", FileName, err)
	}
	switch _, err := os.Lstat(old); {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("checking for %s: %w", LegacyFileName, err)
	}

	if err := foldInTheLog(old); err != nil {
		return fmt.Errorf("folding %s's write-ahead log into it: %w", LegacyFileName, err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Remove(now + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing the %s file left at %s with no database: %w", suffix, FileName, err)
		}
	}
	if err := os.Rename(old, now); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", LegacyFileName, FileName, err)
	}
	if err := syncDir(dataDir); err != nil {
		return fmt.Errorf("flushing the rename of %s to %s: %w", LegacyFileName, FileName, err)
	}
	return nil
}

// foldInTheLog opens the database at path through SQLite, which recovers any
// write-ahead log or hot journal beside it, checkpoints the log into the
// database file and empties it, and closes it. Afterwards the database file
// alone holds every committed row, and the log files beside it are removed.
func foldInTheLog(path string) error {
	db, err := sql.Open("sqlite", fmt.Sprintf("%s?_pragma=busy_timeout(%d)", path, sqlitedb.BusyTimeoutMS))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	// A read first, so SQLite recovers what is beside the file before the
	// checkpoint, and a file that is not a database is refused here.
	var n int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		return err
	}
	var busy, logFrames, checkpointed int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return err
	}
	if busy != 0 {
		return fmt.Errorf("the database is in use, so its log could not be folded in")
	}
	if err := db.Close(); err != nil {
		return err
	}
	// Emptied by the checkpoint, and SQLite normally removes them on the last
	// close. Whatever is left holds nothing.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// syncDir flushes a directory, so a rename in it survives a crash. Not on
// Windows, where a directory cannot be opened to flush and NTFS journals the
// change itself.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
