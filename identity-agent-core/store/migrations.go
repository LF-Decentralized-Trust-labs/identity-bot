package store

import (
	"database/sql"
	"fmt"
	"log"
)

// identityMigrations defines the schema evolution for identity.db (Identity Core domain).
// Follow the same versioned migration pattern as sandbox/migrations.go.
var identityMigrations = []struct {
	Version     int
	Description string
	SQL         string
}{
	{
		Version:     1,
		Description: "Initial Identity Core schema",
		SQL: `
CREATE TABLE IF NOT EXISTS identity (
    aid              TEXT NOT NULL,
    public_key       TEXT NOT NULL,
    next_key_digest  TEXT NOT NULL,
    created          TEXT NOT NULL,
    event_count      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kel (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    aid              TEXT NOT NULL,
    seq_num          INTEGER NOT NULL,
    event_type       TEXT NOT NULL,
    event_json       TEXT NOT NULL,
    public_key       TEXT NOT NULL,
    next_key_digest  TEXT NOT NULL,
    timestamp        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kel_aid ON kel(aid);
CREATE INDEX IF NOT EXISTS idx_kel_seq ON kel(aid, seq_num);

CREATE TABLE IF NOT EXISTS contacts (
    aid              TEXT PRIMARY KEY,
    alias            TEXT NOT NULL DEFAULT '',
    public_key       TEXT NOT NULL DEFAULT '',
    oobi_url         TEXT NOT NULL DEFAULT '',
    verified         INTEGER NOT NULL DEFAULT 0,
    discovered_at    TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT '',
    role             TEXT NOT NULL DEFAULT '',
    jcard_json       TEXT NOT NULL DEFAULT '',
    photo            TEXT NOT NULL DEFAULT '',
    updated_at       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status);

CREATE TABLE IF NOT EXISTS pending_requests (
    aid              TEXT PRIMARY KEY,
    alias            TEXT NOT NULL DEFAULT '',
    public_key       TEXT NOT NULL DEFAULT '',
    oobi_url         TEXT NOT NULL DEFAULT '',
    received_at      TEXT NOT NULL DEFAULT '',
    expires_at       TEXT NOT NULL DEFAULT '',
    error_reason     TEXT NOT NULL DEFAULT '',
    jcard_json       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS profile (
    full_name        TEXT NOT NULL DEFAULT '',
    family_name      TEXT NOT NULL DEFAULT '',
    given_name       TEXT NOT NULL DEFAULT '',
    org              TEXT NOT NULL DEFAULT '',
    title            TEXT NOT NULL DEFAULT '',
    email            TEXT NOT NULL DEFAULT '',
    tel              TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT '',
    photo            TEXT NOT NULL DEFAULT '',
    uid              TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    tunnel_provider          TEXT NOT NULL DEFAULT '',
    ngrok_auth_token         TEXT NOT NULL DEFAULT '',
    cloudflare_tunnel_token  TEXT NOT NULL DEFAULT '',
    tunnel_domain            TEXT NOT NULL DEFAULT '',
    tunnel_extension         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS endpoint (
    url              TEXT NOT NULL DEFAULT '',
    source           TEXT NOT NULL DEFAULT '',
    updated_at       TEXT NOT NULL DEFAULT ''
);
`,
	},
}

// ApplyIdentityMigrations creates the migrations table and applies any pending migrations.
func ApplyIdentityMigrations(db *sql.DB) error {
	if err := ensureIdentityMigrationsTable(db); err != nil {
		return fmt.Errorf("failed to create identity migrations table: %w", err)
	}

	current, err := identityCurrentVersion(db)
	if err != nil {
		return fmt.Errorf("failed to get identity schema version: %w", err)
	}

	for _, m := range identityMigrations {
		if m.Version <= current {
			continue
		}

		log.Printf("[store] Applying identity migration %d: %s", m.Version, m.Description)

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for identity migration %d: %w", m.Version, err)
		}

		if _, err := tx.Exec(m.SQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to apply identity migration %d: %w", m.Version, err)
		}

		if _, err := tx.Exec(
			`INSERT INTO identity_schema_migrations (version, description) VALUES (?, ?)`,
			m.Version, m.Description,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record identity migration %d: %w", m.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit identity migration %d: %w", m.Version, err)
		}

		log.Printf("[store] Identity migration %d applied successfully", m.Version)
	}

	return nil
}

func ensureIdentityMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS identity_schema_migrations (
			version      INTEGER PRIMARY KEY,
			description  TEXT NOT NULL,
			applied_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

func identityCurrentVersion(db *sql.DB) (int, error) {
	var version int
	err := db.QueryRow(
		`SELECT COALESCE(MAX(version), 0) FROM identity_schema_migrations`,
	).Scan(&version)
	if err != nil {
		return 0, err
	}
	return version, nil
}
