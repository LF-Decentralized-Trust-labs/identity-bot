// Package activitylog is the Identity Agent's activity log: the signed,
// chained record of who did what, under whose authority, and of the
// governance decisions taken about them. It is part of the core: the Identity
// Agent is the governance layer, and the record is what anybody outside
// checks it against.
//
// The log is kept in the data directory's sandbox.db, in the invocation_log
// table, where it has always been. That database also holds the sandboxed-app
// add-on's tables, and its schema is one versioned sequence of migrations
// (migrations.go), so this package opens the database and applies that whole
// sequence, and the add-on keeps its own tables on the handle it is given.
package activitylog

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
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

	dbPath := filepath.Join(dataDir, "sandbox.db")
	db, err := sqlitedb.Open(dbPath, sqlitedb.Settings{ForeignKeys: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open sandbox database: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping sandbox database: %w", err)
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
