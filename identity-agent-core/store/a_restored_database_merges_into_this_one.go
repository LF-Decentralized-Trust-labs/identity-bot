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
// identity.db while this process held it open. That overwrite was the only
// path by which a table arrived — it WAS the restore for anything without a
// named section — so any table this package cannot parse, meaning anything a
// build on top of this core keeps in here, came back only if it survived
// intact. Replacing bytes under a live write-ahead log is also undefined,
// though in practice the log checkpoints back over the new file and the known
// tables survive, which is why this showed up as lost tables rather than as
// visible damage.
//
// Attaching instead means SQLite performs the copy, through the open
// connection, in a transaction.
//
// Everything below runs on ONE pinned connection. ATTACH is a property of a
// connection, not of a database, and database/sql hands out whichever pooled
// connection is free — so attaching on one and then querying on another is a
// coin flip that fails with "unknown database restored" as often as the pool
// happens to be warm.
//
// WHAT THIS DELIBERATELY DOES NOT DO. It is additive: a row that exists here
// and not in the backup stays. Restoring is for a machine that has lost an
// identity, not for winding one back, and silently deleting rows somebody
// added since the backup is the worse failure of the two. The exception is
// tables with nothing to match rows on — see replaceWholesale below, where
// additive would mean duplicating.
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

	// A backup from a build newer than this one is refused rather than
	// half-restored.
	//
	// The schema version is bookkeeping in a table like any other, so copying
	// it across records every migration the backup had run as already applied
	// — while the columns those migrations added stay behind, because whole
	// tables are copied and an added column is not a table. The database is
	// then permanently wedged: the binary skips the migrations it needs, and
	// upgrading later does not help because the bookkeeping already says done.
	// The symptom is "table kel has no column named cesr_signature" forever.
	//
	// So the version is never copied, and a newer backup stops here with
	// something a person can act on. Dropping the columns this build does not
	// know about would restore silently and lose whatever was in them.
	theirs, err := schemaVersionOf(ctx, conn, "restored")
	if err != nil {
		return err
	}
	if newest := newestKnownMigration(); theirs > newest {
		return fmt.Errorf(
			"this backup was made by a newer version of the software "+
				"(it expects database version %d, this build understands %d) — "+
				"update the software and run the recovery again", theirs, newest)
	}

	objects, err := objectsIn(ctx, conn, "restored")
	if err != nil {
		return err
	}
	tables, virtual, shadows := classify(objects)
	if len(tables) == 0 && len(virtual) == 0 {
		return fmt.Errorf("the backed-up database has no tables in it")
	}

	// Foreign keys go off for the duration: tables are copied in whatever
	// order sqlite_master lists them, so a child row can legitimately arrive
	// before its parent. This must happen before the transaction opens —
	// SQLite ignores the pragma inside one. It goes back on either way.
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return fmt.Errorf("prepare the restore: %w", err)
	}
	defer conn.ExecContext(ctx, "PRAGMA foreign_keys=ON")

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("prepare the restore: %w", err)
	}
	defer tx.Rollback()

	// Virtual tables first, and their shadow tables are never created
	// directly. A virtual table is stored as several ordinary-looking shadow
	// tables which sqlite_master lists BEFORE it; creating those as plain
	// tables makes the real CREATE VIRTUAL TABLE fail with "shadow table
	// already exists", which used to abort the whole restore. Creating the
	// virtual table makes its own shadows, and the data is then copied into
	// them like any other table, because the shadows are where it lives.
	for _, o := range virtual {
		if err := createIfAbsent(ctx, tx, conn, o); err != nil {
			return err
		}
	}
	for _, o := range tables {
		if err := createIfAbsent(ctx, tx, conn, o); err != nil {
			return err
		}
	}

	for _, o := range append(append([]object{}, tables...), shadows...) {
		if err := copyTable(ctx, tx, conn, o.name); err != nil {
			return err
		}
	}

	// Indexes, triggers and views last, once the tables they refer to exist.
	// These are separate rows in sqlite_master, so copying only tables left a
	// restored database without them — and a dropped UNIQUE index is not
	// cosmetic, it silently starts accepting duplicates.
	for _, o := range objects {
		if o.kind == "table" || o.ddl == "" || isShadow(o.name, virtual) {
			continue
		}
		if _, err := tx.ExecContext(ctx, o.ddl); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("recreate %s %s: %w", o.kind, o.name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit the restore: %w", err)
	}

	// Bring the schema up to what this build expects. The backup was at or
	// below this version — anything above was refused already — so the
	// migrations it has not seen are exactly the ones that still need running.
	if err := ApplyIdentityMigrations(s.db); err != nil {
		return fmt.Errorf("bring the restored database up to date: %w", err)
	}
	return nil
}

type object struct{ kind, name, ddl string }

func objectsIn(ctx context.Context, conn *sql.Conn, schema string) ([]object, error) {
	rows, err := conn.QueryContext(ctx, fmt.Sprintf(
		`SELECT type, name, COALESCE(sql, '') FROM %s.sqlite_master
		  WHERE name NOT LIKE 'sqlite_%%'`, schema))
	if err != nil {
		return nil, fmt.Errorf("read what the backup contains: %w", err)
	}
	defer rows.Close()
	var out []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name, &o.ddl); err != nil {
			return nil, fmt.Errorf("read what the backup contains: %w", err)
		}
		// Never carried: this is bookkeeping about which migrations have run,
		// and it must describe THIS database, not the one in the backup.
		if o.name == "identity_schema_migrations" {
			continue
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func classify(objects []object) (tables, virtual, shadows []object) {
	for _, o := range objects {
		if o.kind != "table" {
			continue
		}
		if strings.Contains(strings.ToUpper(o.ddl), "CREATE VIRTUAL TABLE") {
			virtual = append(virtual, o)
		}
	}
	for _, o := range objects {
		if o.kind != "table" {
			continue
		}
		if strings.Contains(strings.ToUpper(o.ddl), "CREATE VIRTUAL TABLE") {
			continue
		}
		if isShadow(o.name, virtual) {
			shadows = append(shadows, o)
			continue
		}
		tables = append(tables, o)
	}
	return tables, virtual, shadows
}

func isShadow(name string, virtual []object) bool {
	for _, v := range virtual {
		if strings.HasPrefix(name, v.name+"_") {
			return true
		}
	}
	return false
}

func createIfAbsent(ctx context.Context, tx *sql.Tx, conn *sql.Conn, o object) error {
	live, err := columnsOn(ctx, conn, "main", o.name)
	if err != nil {
		return err
	}
	if len(live) > 0 || strings.TrimSpace(o.ddl) == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, o.ddl); err != nil {
		return fmt.Errorf("recreate %s from the backup: %w", o.name, err)
	}
	return nil
}

func copyTable(ctx context.Context, tx *sql.Tx, conn *sql.Conn, name string) error {
	live, err := columnsOn(ctx, conn, "main", name)
	if err != nil {
		return err
	}
	if len(live) == 0 {
		// Creation was skipped because the backup carried no usable DDL.
		return nil
	}
	backed, err := columnsOn(ctx, conn, "restored", name)
	if err != nil {
		return err
	}

	// Only the columns both sides have. A backup taken before a migration
	// lacks columns this database now has, and neither should fail a restore.
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
		return nil
	}

	// A table with nothing to match rows on gets replaced rather than added
	// to. INSERT OR REPLACE resolves against a primary key or a unique index;
	// with neither there is no conflict to detect, so every restore appends a
	// second copy of every row. Four tables in this schema are declared with
	// no primary key — identity, profile, settings and endpoint — and two of
	// them, profile and endpoint, have no parsed section either, so this copy
	// is the only way they come back at all. Appending left the local
	// placeholder row first and the restored one unreachable behind it, which
	// reads as the backup simply not containing a profile.
	wholesale, err := replaceWholesale(ctx, conn, name)
	if err != nil {
		return err
	}
	if wholesale {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM main."%s"`, name)); err != nil {
			return fmt.Errorf("clear the %s table before restoring it: %w", name, err)
		}
	}

	cols := strings.Join(shared, ", ")
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(
		`INSERT OR REPLACE INTO main."%s" (%s) SELECT %s FROM restored."%s"`,
		name, cols, cols, name)); err != nil {
		return fmt.Errorf("restore the %s table: %w", name, err)
	}
	return nil
}

// replaceWholesale reports whether a table has no way to tell one row from
// another — no primary key and no unique index — so that inserting is the
// only outcome INSERT OR REPLACE can produce.
func replaceWholesale(ctx context.Context, conn *sql.Conn, table string) (bool, error) {
	rows, err := conn.QueryContext(ctx, fmt.Sprintf(`PRAGMA main.table_info("%s")`, table))
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", table, err)
	}
	for rows.Next() {
		var (
			cid       int
			name, typ string
			notNull   int
			dflt      any
			pk        int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return false, fmt.Errorf("inspect %s: %w", table, err)
		}
		if pk > 0 {
			rows.Close()
			return false, nil
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}

	idx, err := conn.QueryContext(ctx, fmt.Sprintf(`PRAGMA main.index_list("%s")`, table))
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", table, err)
	}
	defer idx.Close()
	for idx.Next() {
		var (
			seq          int
			name, origin string
			unique       int
			partial      int
		)
		if err := idx.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return false, fmt.Errorf("inspect %s: %w", table, err)
		}
		if unique == 1 && partial == 0 {
			return false, nil
		}
	}
	return true, idx.Err()
}

func schemaVersionOf(ctx context.Context, conn *sql.Conn, schema string) (int, error) {
	var v int
	err := conn.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COALESCE(MAX(version), 0) FROM %s.identity_schema_migrations`, schema)).Scan(&v)
	if err != nil {
		// A backup with no migrations table predates it, or is not this
		// schema at all. Either way it is not newer than this build.
		return 0, nil
	}
	return v, nil
}

func newestKnownMigration() int {
	newest := 0
	for _, m := range identityMigrations {
		if m.Version > newest {
			newest = m.Version
		}
	}
	return newest
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
