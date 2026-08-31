package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ImportSnapshot brings the contents of a backed-up database into this one.
//
// The restore used to write the archived bytes straight over identity.db while
// this process held it open. That overwrite was the only path by which a table
// arrived — it WAS the restore for anything without a named section — so any
// table this package cannot parse, meaning anything a build on top of this
// core keeps in here, came back only if it survived intact. Replacing bytes
// under a live write-ahead log is also undefined, though in practice the log
// checkpoints back over the new file and the known tables survive, which is
// why this showed up as lost tables rather than as visible damage.
//
// The backup is migrated to this build's schema BEFORE anything is copied.
// That ordering is the whole design. Copying row by row into an already-
// migrated database means intersecting columns, and a migration that renames a
// column or adds a NOT NULL one makes that intersection wrong rather than
// merely lossy: the rename leaves the old name unmatched and the insert omits
// a column that cannot be null, so an ordinary older backup fails the restore
// with a constraint error. Migrations exist to transform data across exactly
// those changes, so the backup is brought forward by running them, and the
// copy then happens between two databases with the same schema.
//
// Everything below runs on ONE pinned connection. ATTACH is a property of a
// connection, not of a database, and database/sql hands out whichever pooled
// connection is free — so attaching on one and then querying on another is a
// coin flip that fails with "unknown database restored" as often as the pool
// happens to be warm.
//
// It is additive: a row that exists here and not in the backup stays. Restoring
// is for a machine that has lost an identity, not for winding one back, and
// silently deleting rows somebody added since the backup is the worse failure.
// Two kinds of table are the exception, both because adding would corrupt
// rather than accumulate — see copyTable.
func (s *SQLiteStore) ImportSnapshot(path string) error {
	// Safe to have been done already: migrations skip versions the file has,
	// and the two refusals below are pure checks. The restore runs this in its
	// preflight so that a backup which cannot be used is refused before
	// anything is written, and calling it again here keeps ImportSnapshot
	// correct for any other caller.
	if err := PrepareSnapshotForImport(path); err != nil {
		return err
	}

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

	objects, err := objectsIn(ctx, conn, "restored")
	if err != nil {
		return err
	}
	var virtual, ordinary []object
	for _, o := range objects {
		switch {
		case o.kind != "table":
		case o.virtual:
			virtual = append(virtual, o)
		default:
			ordinary = append(ordinary, o)
		}
	}
	if len(ordinary) == 0 && len(virtual) == 0 {
		return fmt.Errorf("the backed-up database has no tables in it")
	}

	// Which tables belong to a virtual table, established by building each
	// virtual table in a scratch database and seeing what appears beside it.
	//
	// These cannot be told apart by name. A virtual table stores itself in
	// several ordinary-looking tables, and guessing which they are from a name
	// prefix silently swallows any real table that happens to share it — with
	// a virtual table `notes`, a downstream table `notes_archive` is not a
	// shadow of it, and treating it as one loses it completely. Asking SQLite
	// to create the thing and observing the result cannot be wrong about it.
	shadow, err := shadowTablesOf(virtual)
	if err != nil {
		return err
	}

	// Foreign keys go off for the duration: tables are copied in whatever
	// order sqlite_master lists them, so a child row can legitimately arrive
	// before its parent. This must happen before the transaction opens —
	// SQLite ignores the pragma inside one. It goes back on either way.
	// Put back what this connection had, rather than switching enforcement on.
	// NewSQLiteStore sets its pragmas with db.Exec, which reaches whichever
	// single pooled connection served it, so foreign_keys is already on for
	// some connections and off for others. Ending with an unconditional ON
	// newly enables it on a connection that did not have it, and afterwards
	// whether a write is checked depends on which connection the pool hands
	// out.
	var hadForeignKeys int
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&hadForeignKeys); err != nil {
		return fmt.Errorf("prepare the restore: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return fmt.Errorf("prepare the restore: %w", err)
	}
	defer conn.ExecContext(ctx, fmt.Sprintf("PRAGMA foreign_keys=%d", hadForeignKeys))

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("prepare the restore: %w", err)
	}
	defer tx.Rollback()

	// Virtual tables first: creating one creates the tables it stores itself
	// in, which the copy below then fills. Creating those directly instead
	// makes the real CREATE VIRTUAL TABLE fail with "shadow table already
	// exists", which used to abort the entire restore.
	for _, o := range virtual {
		if err := createIfAbsent(ctx, tx, conn, o); err != nil {
			return err
		}
	}
	for _, o := range ordinary {
		if err := createIfAbsent(ctx, tx, conn, o); err != nil {
			return err
		}
	}
	// Indexes, triggers and views once their tables exist and BEFORE the rows
	// arrive. These are separate rows in sqlite_master, so copying only tables
	// left a restored database without them — and a dropped UNIQUE index is
	// not cosmetic, it silently starts accepting duplicates. They go in first
	// because the copy below asks whether a table has anything to match rows
	// on, and a unique index is one of the answers.
	for _, o := range objects {
		if o.kind == "table" || o.ddl == "" {
			continue
		}
		if err := execOneStatementTx(ctx, tx, o.ddl, o.name); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("recreate %s %s: %w", o.kind, o.name, err)
		}
	}

	for _, o := range ordinary {
		if err := copyTable(ctx, tx, conn, o.name, shadow[o.name]); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit the restore: %w", err)
	}
	return nil
}

// PrepareSnapshotForImport runs this build's migrations against a backup and
// refuses one that cannot be used.
//
// It MUTATES the file at path, which is why the restore writes the archive's
// database section to a working copy rather than pointing this at anything it
// wants to keep.
//
// Separate from ImportSnapshot so that it can run in a preflight. Everything
// that makes a backup unusable rather than merely old is decided here — too
// new for this build, not an identity database, a migration that will not
// apply — and deciding it early is what lets the restore refuse before it has
// written anything. Idempotent: running it twice on the same file is a check
// and then a no-op.
func PrepareSnapshotForImport(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open the backed-up database: %w", err)
	}
	defer db.Close()

	// Rolling the journal into the file itself means closing this leaves one
	// self-contained file, which is what the copy below expects to attach.
	if _, err := db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		return fmt.Errorf("open the backed-up database: %w", err)
	}

	// Every identity database has this table — it is created when the store is
	// opened, before anything else can happen. Its absence means this is not
	// one, and merging an unrelated database into the identity store wholesale
	// is not something to do quietly.
	var present string
	if err := db.QueryRow(
		`SELECT name FROM sqlite_master
		  WHERE type='table' AND name='identity_schema_migrations'`).Scan(&present); err != nil {
		return fmt.Errorf(
			"this backup does not look like an identity database — " +
				"it has no schema history in it")
	}

	var theirs int
	if err := db.QueryRow(
		`SELECT COALESCE(MAX(version), 0) FROM identity_schema_migrations`).Scan(&theirs); err != nil {
		return fmt.Errorf("read the backup's schema history: %w", err)
	}
	if newest := newestKnownMigration(); theirs > newest {
		return fmt.Errorf(
			"this backup was made by a newer version of the software "+
				"(it expects database version %d, this build understands %d) — "+
				"update the software and run the recovery again", theirs, newest)
	}

	// Bring it forward. This is where a renamed column is renamed and a new
	// NOT NULL column gets its default, so that the copy afterwards is between
	// two identical schemas rather than an intersection of two different ones.
	if err := ApplyIdentityMigrations(db); err != nil {
		return fmt.Errorf("bring the backup up to this version: %w", err)
	}
	return nil
}

type object struct {
	kind, name, ddl string
	virtual         bool
}

func objectsIn(ctx context.Context, conn *sql.Conn, schema string) ([]object, error) {
	// rootpage is 0 for a virtual table and non-zero for a real one. Searching
	// the DDL text for "CREATE VIRTUAL TABLE" instead misreads any ordinary
	// table that merely mentions it — in a default value, a check constraint
	// or a comment — and a table classified virtual is never copied, so its
	// schema arrives and its rows do not.
	rows, err := conn.QueryContext(ctx, fmt.Sprintf(
		`SELECT type, name, COALESCE(sql, ''), rootpage = 0
		   FROM %s.sqlite_master WHERE name NOT LIKE 'sqlite_%%'`, schema))
	if err != nil {
		return nil, fmt.Errorf("read what the backup contains: %w", err)
	}
	defer rows.Close()
	var out []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name, &o.ddl, &o.virtual); err != nil {
			return nil, fmt.Errorf("read what the backup contains: %w", err)
		}
		// Never carried: this is bookkeeping about which migrations have run,
		// and it describes the database it came from rather than this one.
		//
		// It is belt and braces rather than load-bearing, and worth saying so:
		// the backup has just been migrated to this build's version, so the two
		// tables now agree and copying it would change nothing. It earns its
		// place only if that ever stops being true — which is exactly the
		// condition under which copying it wedges the schema permanently.
		if o.name == "identity_schema_migrations" {
			continue
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// shadowTablesOf reports the tables SQLite creates to store a virtual table in.
func shadowTablesOf(virtual []object) (map[string]bool, error) {
	shadow := map[string]bool{}
	if len(virtual) == 0 {
		return shadow, nil
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("inspect the backup's tables: %w", err)
	}
	defer db.Close()

	// Pinned, because every connection to ":memory:" is a SEPARATE empty
	// database. Creating the virtual table on one pooled connection and then
	// listing tables on another reports nothing, silently — and a silently
	// empty shadow map merges those tables row by row, which is what corrupts
	// the index. Sequential use happens to reuse one idle connection today;
	// nothing holds it there.
	probe, err := db.Conn(context.Background())
	if err != nil {
		return nil, fmt.Errorf("inspect the backup's tables: %w", err)
	}
	defer probe.Close()

	for _, v := range virtual {
		before, err := tableNamesIn(probe)
		if err != nil {
			return nil, err
		}
		if err := execOneStatement(context.Background(), probe, v.ddl, v.name); err != nil {
			// A module this build does not have. The virtual table will fail
			// to create during the restore too, and that error is the one
			// worth reporting; nothing is assumed about its tables here.
			continue
		}
		after, err := tableNamesIn(probe)
		if err != nil {
			return nil, err
		}
		for name := range after {
			if !before[name] && name != v.name {
				shadow[name] = true
			}
		}
	}
	return shadow, nil
}

func tableNamesIn(conn *sql.Conn) (map[string]bool, error) {
	rows, err := conn.QueryContext(context.Background(),
		`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return nil, fmt.Errorf("inspect the backup's tables: %w", err)
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("inspect the backup's tables: %w", err)
		}
		names[n] = true
	}
	return names, rows.Err()
}

// execOneStatement runs schema text from the backup, and only if it is one
// statement.
//
// sqlite_master.sql is free text. It is normally exactly what SQLite recorded
// when the object was created, but PRAGMA writable_schema lets it be anything,
// and this code hands it to Exec against the live identity database. The
// previous restore wrote bytes over a file; this one executes the artifact's
// schema, which is a surface that did not exist before. A second statement
// smuggled in behind a semicolon runs with the same access the restore has.
//
// The archive is opened with the owner's own key, so this is not a remote
// attack — it is containment for an artifact that has been off this machine.
// Refusing anything that is not a single statement creating the object
// sqlite_master says it is costs nothing legitimate.
func execOneStatement(ctx context.Context, conn *sql.Conn, ddl, name string) error {
	if !isOneStatement(ddl) {
		return fmt.Errorf(
			"the backup's definition of %q carries more than one statement", name)
	}
	_, err := conn.ExecContext(ctx, ddl)
	return err
}

func execOneStatementTx(ctx context.Context, tx *sql.Tx, ddl, name string) error {
	if !isOneStatement(ddl) {
		return fmt.Errorf(
			"the backup's definition of %q carries more than one statement", name)
	}
	_, err := tx.ExecContext(ctx, ddl)
	return err
}

// isOneStatement reports whether ddl contains a single statement, ignoring
// semicolons inside string literals, identifiers and comments.
func isOneStatement(ddl string) bool {
	rest := strings.TrimSpace(ddl)
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '\'', '"', '`':
			quote := rest[i]
			i++
			for i < len(rest) && rest[i] != quote {
				i++
			}
		case '[':
			for i < len(rest) && rest[i] != ']' {
				i++
			}
		case '-':
			if i+1 < len(rest) && rest[i+1] == '-' {
				for i < len(rest) && rest[i] != '\n' {
					i++
				}
			}
		case '/':
			if i+1 < len(rest) && rest[i+1] == '*' {
				i += 2
				for i+1 < len(rest) && !(rest[i] == '*' && rest[i+1] == '/') {
					i++
				}
				i++
			}
		case ';':
			// Trailing semicolons are fine; anything after one is not.
			return strings.TrimSpace(rest[i+1:]) == ""
		}
	}
	return true
}

func createIfAbsent(ctx context.Context, tx *sql.Tx, conn *sql.Conn, o object) error {
	live, err := columnsOn(ctx, conn, "main", o.name)
	if err != nil {
		return err
	}
	if len(live) > 0 || strings.TrimSpace(o.ddl) == "" {
		return nil
	}
	if err := execOneStatementTx(ctx, tx, o.ddl, o.name); err != nil {
		return fmt.Errorf("recreate %s from the backup: %w", o.name, err)
	}
	return nil
}

func copyTable(ctx context.Context, tx *sql.Tx, conn *sql.Conn, name string, isShadow bool) error {
	live, err := columnsOn(ctx, conn, "main", name)
	if err != nil {
		return err
	}
	if len(live) == 0 {
		return nil // creation was skipped: the backup carried no usable DDL
	}
	backed, err := columnsOn(ctx, conn, "restored", name)
	if err != nil {
		return err
	}
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

	// Two kinds of table are replaced rather than added to, and in both cases
	// adding produces something wrong rather than something merely bigger.
	//
	// A table with no primary key and no unique index gives INSERT OR REPLACE
	// nothing to conflict on, so every restore appends another copy of every
	// row. Four tables here are declared that way, and profile and endpoint
	// have no parsed section either — so the local placeholder stayed at the
	// lower rowid and the restored row sat unreachable behind it, which reads
	// exactly like a backup that contained no profile.
	//
	// A table storing a virtual table holds an internal structure keyed by
	// row ids that mean nothing outside it. Merging two of them by row id
	// interleaves two unrelated indexes, and the result passes an integrity
	// check while having quietly lost entries from both.
	wholesale := isShadow
	if !wholesale && singleRowCoreTables[name] {
		wholesale, err = hasNothingToMatchRowsOn(ctx, conn, name)
		if err != nil {
			return err
		}
	}
	if wholesale {
		// Only when the backup actually has something to put back. Clearing a
		// table the backup left empty deletes what is here and restores
		// nothing — and for profile and endpoint there is no parsed section to
		// repair it afterwards, so an ordinary restore from a machine that
		// never set a profile would wipe the local one.
		var incoming int
		if err := tx.QueryRowContext(ctx, fmt.Sprintf(
			`SELECT COUNT(*) FROM restored."%s"`, name)).Scan(&incoming); err != nil {
			return fmt.Errorf("read the %s table from the backup: %w", name, err)
		}
		if incoming == 0 {
			return nil
		}
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

// singleRowCoreTables are the tables of this schema that hold exactly one row
// and are declared with no primary key.
//
// Only these are cleared before copying. A downstream table with no primary
// key is left additive even though restoring it twice duplicates its rows,
// because this core cannot know what such a table is for — an append-only log
// or an audit trail written on this machine since the backup would be deleted,
// and duplicating rows is recoverable in a way that deleting them is not. It
// is the same reason the sweep carries files it does not recognise.
var singleRowCoreTables = map[string]bool{
	"identity": true, "profile": true, "settings": true, "endpoint": true,
}

// hasNothingToMatchRowsOn reports whether a table has no primary key and no
// unique index, so that inserting is the only outcome INSERT OR REPLACE can
// produce.
func hasNothingToMatchRowsOn(ctx context.Context, conn *sql.Conn, table string) (bool, error) {
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
