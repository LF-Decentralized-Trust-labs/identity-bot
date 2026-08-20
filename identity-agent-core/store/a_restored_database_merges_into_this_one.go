package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ImportSnapshot brings the contents of a backed-up database into this one.
//
// The restore used to do this by writing the archived bytes straight over
// identity.db while this process held it open.
//
// One consequence is proven and one is not, and it is worth being exact about
// which is which.
//
// PROVEN: everything in the archive that this package cannot parse was lost.
// The overwrite is the only path by which a table arrives, and it ran before
// nothing — it WAS the restore for anything without a named section. Any table
// a build on top of this core keeps in here came back only if the overwrite
// survived, and the sections restored afterwards through this store were
// written into a database that had just been replaced underneath them. A test
// covers this: create a table this package has never heard of, back up,
// restore, and it is gone.
//
// NOT PROVEN, and left in place as a hazard rather than a symptom: replacing
// the bytes under a live WAL connection is undefined. The -wal beside the file
// describes pages of the database that was there a moment ago. In practice the
// write-ahead log checkpoints back over the new file on close and the known
// tables survive, which is why this does not reliably show up as damage — but
// "it happens to work because the log wins" is not a property to depend on for
// the one operation that has to work when everything else has been lost.
//
// Attaching instead means SQLite performs the copy, through the open
// connection, in a transaction. Tables the archive holds that this database
// has never heard of are created and copied too: this core cannot know what
// software built on top of it keeps in here, and dropping those tables is the
// same failure the tier-3 sweep exists to prevent.
//
// Everything below runs on ONE pinned connection. ATTACH is a property of a
// connection, not of a database, and database/sql hands out whichever pooled
// connection is free — so attaching on one and then querying on another is a
// coin flip that fails with "unknown database restored" exactly as often as
// the pool happens to be warm.
func (s *SQLiteStore) ImportSnapshot(path string) error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("prepare the restore: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "ATTACH DATABASE ? AS restored", path); err != nil {
		return fmt.Errorf("open the backed-up database: %w", err)
	}
	defer conn.ExecContext(ctx, "DETACH DATABASE restored")

	rows, err := conn.QueryContext(ctx,
		`SELECT name, sql FROM restored.sqlite_master
		  WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return fmt.Errorf("read what the backup contains: %w", err)
	}
	type table struct {
		name string
		ddl  sql.NullString
	}
	var tables []table
	for rows.Next() {
		var t table
		if err := rows.Scan(&t.name, &t.ddl); err != nil {
			rows.Close()
			return fmt.Errorf("read what the backup contains: %w", err)
		}
		tables = append(tables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read what the backup contains: %w", err)
	}
	if len(tables) == 0 {
		return fmt.Errorf("the backed-up database has no tables in it")
	}

	// Foreign keys go off for the duration: the tables are copied in whatever
	// order sqlite_master lists them, so a child row can legitimately arrive
	// before its parent. They go back on afterwards either way.
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return fmt.Errorf("prepare the restore: %w", err)
	}
	defer conn.ExecContext(ctx, "PRAGMA foreign_keys=ON")

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("prepare the restore: %w", err)
	}
	defer tx.Rollback()

	for _, t := range tables {
		live, err := columnsOn(ctx, conn, "main", t.name)
		if err != nil {
			return err
		}
		if len(live) == 0 {
			// A table only the backup has. Create it here as it was there,
			// then every column comes across.
			if !t.ddl.Valid || strings.TrimSpace(t.ddl.String) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, t.ddl.String); err != nil {
				return fmt.Errorf("recreate %s from the backup: %w", t.name, err)
			}
			if live, err = columnsOn(ctx, conn, "main", t.name); err != nil {
				return err
			}
		}

		backed, err := columnsOn(ctx, conn, "restored", t.name)
		if err != nil {
			return err
		}

		// Only the columns both sides have. A backup taken before a migration
		// lacks columns this database now has, and one taken after an upgrade
		// may carry columns it does not — neither should fail the restore.
		var shared []string
		for _, c := range backed {
			for _, l := range live {
				if c == l {
					shared = append(shared, `"`+c+`"`)
					break
				}
			}
		}
		if len(shared) == 0 {
			continue
		}
		cols := strings.Join(shared, ", ")
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(
			`INSERT OR REPLACE INTO main."%s" (%s) SELECT %s FROM restored."%s"`,
			t.name, cols, cols, t.name)); err != nil {
			return fmt.Errorf("restore the %s table: %w", t.name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit the restore: %w", err)
	}
	return nil
}

func columnsOn(ctx context.Context, conn *sql.Conn, schema, table string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, fmt.Sprintf(`PRAGMA %s.table_info("%s")`, schema, table))
	if err != nil {
		return nil, fmt.Errorf("inspect %s.%s: %w", schema, table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			dflt       any
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &primaryKey); err != nil {
			return nil, fmt.Errorf("inspect %s.%s: %w", schema, table, err)
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}
