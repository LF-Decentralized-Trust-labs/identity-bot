// Package sqlitedb is the one way this agent opens a SQLite database.
//
// The driver applies a setting to every connection the pool opens only when
// it is given in the connection string as _pragma=name(value). A PRAGMA run
// once with Exec reaches whichever single connection ran it, and parameters in
// other drivers' forms (_busy_timeout, _journal_mode) are ignored outright, so
// every other connection waited for nothing on a busy database and failed at
// once, and journaled in the default mode.
package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// BusyTimeoutMS is how long a connection waits for a busy database.
const BusyTimeoutMS = 5000

// Settings are what differs between the databases this agent keeps.
type Settings struct {
	// ForeignKeys enforces the database's foreign keys.
	ForeignKeys bool
}

// Open opens the SQLite database at path with every setting applied to every
// connection.
func Open(path string, s Settings) (*sql.DB, error) {
	return sql.Open("sqlite", DSN(path, s))
}

// DSN is the connection string Open uses.
func DSN(path string, s Settings) string {
	pragmas := []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(NORMAL)"}
	if s.ForeignKeys {
		pragmas = append(pragmas, "foreign_keys(1)")
	}
	return path + "?_pragma=" + strings.Join(pragmas, "&_pragma=")
}

// InForce reads back, from each of n separate connections of db, the
// settings Open applies, as "busy_timeout journal_mode synchronous
// foreign_keys", so a store can show every connection has them.
func InForce(db *sql.DB, n int) ([]string, error) {
	ctx := context.Background()
	var conns []*sql.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	var out []string
	for i := 0; i < n; i++ {
		c, err := db.Conn(ctx)
		if err != nil {
			return nil, err
		}
		var busy, sync, fk int
		var mode string
		for q, dst := range map[string]interface{}{
			"PRAGMA busy_timeout": &busy, "PRAGMA journal_mode": &mode,
			"PRAGMA synchronous": &sync, "PRAGMA foreign_keys": &fk,
		} {
			if err := c.QueryRowContext(ctx, q).Scan(dst); err != nil {
				c.Close()
				return nil, err
			}
		}
		out = append(out, fmt.Sprintf("%d %s %d %d", busy, mode, sync, fk))
		if db.Stats().MaxOpenConnections == 1 {
			c.Close() // one at a time where only one may be open
		} else {
			conns = append(conns, c)
		}
	}
	return out, nil
}
