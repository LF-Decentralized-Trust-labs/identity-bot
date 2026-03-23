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
	{
		Version:     2,
		Description: "Add contact_kels table and cesr_signature column to kel",
		SQL: `
ALTER TABLE kel ADD COLUMN cesr_signature TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS contact_kels (
    aid                TEXT PRIMARY KEY,
    kel_json           TEXT NOT NULL DEFAULT '[]',
    kel_verified       INTEGER NOT NULL DEFAULT 0,
    current_public_key TEXT NOT NULL DEFAULT '',
    events_validated   INTEGER NOT NULL DEFAULT 0,
    validation_errors  TEXT NOT NULL DEFAULT '[]',
    validated_at       TEXT NOT NULL DEFAULT ''
);
`,
	},
	{
		Version:     3,
		Description: "Add credentials table for ACDC credential issuance",
		SQL: `
CREATE TABLE IF NOT EXISTS credentials (
    said           TEXT PRIMARY KEY,
    issuer_aid     TEXT NOT NULL DEFAULT '',
    holder_aid     TEXT NOT NULL DEFAULT '',
    schema_said    TEXT NOT NULL DEFAULT '',
    acdc_json      TEXT NOT NULL DEFAULT '',
    ixn_said       TEXT NOT NULL DEFAULT '',
    cesr_signature TEXT NOT NULL DEFAULT '',
    issued_at      TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'issued'
);

CREATE INDEX IF NOT EXISTS idx_credentials_issuer ON credentials(issuer_aid);
CREATE INDEX IF NOT EXISTS idx_credentials_holder ON credentials(holder_aid);
`,
	},
	{
		Version:     4,
		Description: "Add presentations table for verifiable credential presentations",
		SQL: `
CREATE TABLE IF NOT EXISTS presentations (
    said                   TEXT PRIMARY KEY,
    credential_said        TEXT NOT NULL DEFAULT '',
    holder_aid             TEXT NOT NULL DEFAULT '',
    issuer_aid             TEXT NOT NULL DEFAULT '',
    presentation_json_b64  TEXT NOT NULL DEFAULT '',
    cesr_signature         TEXT NOT NULL DEFAULT '',
    created_at             TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'created'
);

CREATE INDEX IF NOT EXISTS idx_presentations_credential ON presentations(credential_said);
CREATE INDEX IF NOT EXISTS idx_presentations_holder ON presentations(holder_aid);
`,
	},
	{
		Version:     5,
		Description: "Add witness_receipts table for KERL phase 7",
		SQL: `
CREATE TABLE IF NOT EXISTS witness_receipts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_said      TEXT NOT NULL,
    witness_aid     TEXT NOT NULL,
    cesr_signature  TEXT NOT NULL,
    received_at     TEXT NOT NULL DEFAULT '',
    UNIQUE(event_said, witness_aid)
);

CREATE INDEX IF NOT EXISTS idx_witness_receipts_event ON witness_receipts(event_said);
`,
	},
	{
		Version:     6,
		Description: "Contacts: replace role/trusted with contact_type/is_witness; add tasks table",
		SQL: `
DROP TABLE IF EXISTS contacts;
CREATE TABLE contacts (
    aid           TEXT PRIMARY KEY,
    alias         TEXT NOT NULL DEFAULT '',
    public_key    TEXT NOT NULL DEFAULT '',
    oobi_url      TEXT NOT NULL DEFAULT '',
    verified      INTEGER NOT NULL DEFAULT 0,
    discovered_at TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT '',
    contact_type  TEXT NOT NULL DEFAULT 'general',
    is_witness    INTEGER NOT NULL DEFAULT 0,
    jcard_json    TEXT NOT NULL DEFAULT '',
    photo         TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status);
CREATE INDEX IF NOT EXISTS idx_contacts_type ON contacts(contact_type);

CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    contact_aid TEXT NOT NULL DEFAULT '',
    progress    INTEGER NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
`,
	},
	{
		Version:     7,
		Description: "Add share_actions table with default engagement actions",
		SQL: `
CREATE TABLE IF NOT EXISTS share_actions (
    id          TEXT PRIMARY KEY,
    action_key  TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL DEFAULT '',
    subtitle    TEXT NOT NULL DEFAULT '',
    icon        TEXT NOT NULL DEFAULT '',
    is_enabled  INTEGER NOT NULL DEFAULT 1,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL DEFAULT ''
);

INSERT OR IGNORE INTO share_actions (id, action_key, name, subtitle, icon, is_enabled, sort_order, updated_at) VALUES
    ('sa-add-contact',      'add_contact',      'Add Contact',      'Generate a shareable link so others can add you as a contact', 'person_add_outlined', 1, 1, datetime('now')),
    ('sa-show-id',          'show_id',          'Show ID',          'Display your identity QR code',                               'badge_outlined',      0, 2, datetime('now')),
    ('sa-request-payment',  'request_payment',  'Request Payment',  'Send a payment request to a contact',                        'payment_outlined',    0, 3, datetime('now')),
    ('sa-share-file',       'share_file',       'Share a File',     'Send an encrypted file to a contact',                        'attach_file',         0, 4, datetime('now')),
    ('sa-share-credential', 'share_credential', 'Share Credential', 'Present a verifiable credential',                            'verified_outlined',   0, 5, datetime('now'));
`,
	},
	{
		Version:     8,
		Description: "Add guardianships table",
		SQL: `
CREATE TABLE IF NOT EXISTS guardianships (
    id                    TEXT PRIMARY KEY,
    type                  TEXT NOT NULL DEFAULT '',
    guardian_aid          TEXT NOT NULL DEFAULT '',
    dependent_aid         TEXT NOT NULL DEFAULT '',
    dependent_name        TEXT NOT NULL DEFAULT '',
    delegated_aid_prefix  TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'active',
    hosting_type          TEXT NOT NULL DEFAULT '',
    hosting_url           TEXT NOT NULL DEFAULT '',
    created_at            TEXT NOT NULL DEFAULT '',
    updated_at            TEXT NOT NULL DEFAULT '',
    emancipation_json     TEXT NOT NULL DEFAULT '{}',
    co_guardians_json     TEXT NOT NULL DEFAULT '[]',
    multisig_threshold    INTEGER NOT NULL DEFAULT 0,
    metadata_json         TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_guardianships_guardian ON guardianships(guardian_aid);
CREATE INDEX IF NOT EXISTS idx_guardianships_dependent ON guardianships(dependent_aid);
CREATE INDEX IF NOT EXISTS idx_guardianships_status ON guardianships(status);
`,
	},
	{
		Version:     9,
		Description: "Credentials: add multi-format columns; add credential_schemas table",
		SQL: `
ALTER TABLE credentials ADD COLUMN format          TEXT NOT NULL DEFAULT 'acdc';
ALTER TABLE credentials ADD COLUMN credential_type TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN issuer_name     TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN issuer_logo_url TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN expiry_date     TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN raw_json        TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS credential_schemas (
    said        TEXT PRIMARY KEY,
    schema_json TEXT NOT NULL DEFAULT '',
    fetched_at  TEXT NOT NULL DEFAULT ''
);
`,
	},
	{
		Version:     10,
		Description: "Guardianship: add credential_said column for chain-of-trust linkage",
		SQL: `
ALTER TABLE guardianships ADD COLUMN credential_said TEXT NOT NULL DEFAULT '';
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
