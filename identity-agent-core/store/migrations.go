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
    ('sa-credential-request', 'credential_request', 'Credential Request', 'Present a verifiable credential (SEAM-7)', 'verified_outlined', 0, 5, datetime('now'));
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
	{
		Version:     11,
		Description: "Add service_providers table",
		SQL: `
CREATE TABLE IF NOT EXISTS service_providers (
    id                 TEXT PRIMARY KEY,
    provider_name      TEXT NOT NULL DEFAULT '',
    provider_aid       TEXT NOT NULL DEFAULT '',
    category           TEXT NOT NULL DEFAULT '',
    display_name       TEXT NOT NULL DEFAULT '',
    endpoint_url       TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'available',
    health             TEXT NOT NULL DEFAULT 'unknown',
    health_checked_at  TEXT NOT NULL DEFAULT '',
    company_hq         TEXT NOT NULL DEFAULT '',
    server_region      TEXT NOT NULL DEFAULT '',
    identity_level     INTEGER NOT NULL DEFAULT 0,
    grape_score        INTEGER NOT NULL DEFAULT 0,
    capabilities_json  TEXT NOT NULL DEFAULT '[]',
    terms_url          TEXT NOT NULL DEFAULT '',
    terms_accepted_at  TEXT NOT NULL DEFAULT '',
    terms_version      TEXT NOT NULL DEFAULT '',
    connected_at       TEXT NOT NULL DEFAULT '',
    configuration_json TEXT NOT NULL DEFAULT '{}',
    is_default         INTEGER NOT NULL DEFAULT 0,
    source             TEXT NOT NULL DEFAULT 'manual',
    created_at         TEXT NOT NULL DEFAULT '',
    updated_at         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_service_providers_category ON service_providers(category);
CREATE INDEX IF NOT EXISTS idx_service_providers_status ON service_providers(status);

INSERT OR IGNORE INTO service_providers (id, provider_name, provider_aid, category, display_name, endpoint_url, status, health, company_hq, server_region, identity_level, grape_score, capabilities_json, terms_url, is_default, source, created_at, updated_at) VALUES
    ('sp-grapeid-infra',   'Grape ID', '', 'infrastructure', 'Grape ID Infrastructure', 'https://grapeid.org/api/infrastructure', 'available', 'unknown', 'United States', 'US-West', 0, 0, '["host_instance","tee_enclave","auto_provision"]',       'https://grapeid.org/terms', 1, 'builtin', datetime('now'), datetime('now')),
    ('sp-grapeid-witness', 'Grape ID', '', 'witness',        'Grape ID Witness',        'https://keri.grapeid.org',               'available', 'unknown', 'United States', 'US-West', 0, 0, '["witness_events","store_kel_replica","serve_kel"]',     'https://grapeid.org/terms', 1, 'builtin', datetime('now'), datetime('now')),
    ('sp-grapeid-hsm',     'Grape ID', '', 'cloud_hsm',      'Grape ID Cloud HSM',      'https://grapeid.org/api/hsm',            'available', 'unknown', 'United States', 'US-West', 0, 0, '["key_storage","sign_operations","seal_unseal"]',        'https://grapeid.org/terms', 1, 'builtin', datetime('now'), datetime('now')),
    ('sp-grapeid-tunnel',  'Grape ID', '', 'tunneling',       'Grape ID Tunnel',         'https://grapeid.org/api/tunnel',          'available', 'unknown', 'United States', 'US-West', 0, 0, '["tunnel_chisel","custom_domain"]',                      'https://grapeid.org/terms', 1, 'builtin', datetime('now'), datetime('now'));
`,
	},
	{
		Version:     12,
		Description: "KERI Watchers: kel_first_seen, duplicity_alerts, watcher config",
		SQL: `
CREATE TABLE IF NOT EXISTS kel_first_seen (
    aid                TEXT     NOT NULL,
    sequence_num       INTEGER  NOT NULL,
    kel_digest         TEXT     NOT NULL,
    first_seen_at      TEXT     NOT NULL,
    last_confirmed_at  TEXT     NOT NULL,
    seen_count         INTEGER  DEFAULT 1,
    source_type        TEXT     NOT NULL,
    source_url         TEXT,
    PRIMARY KEY (aid, sequence_num)
);
CREATE INDEX IF NOT EXISTS idx_kel_first_seen_aid ON kel_first_seen(aid);

CREATE TABLE IF NOT EXISTS duplicity_alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    aid             TEXT     NOT NULL,
    sequence_num    INTEGER  NOT NULL,
    our_digest      TEXT     NOT NULL,
    their_digest    TEXT     NOT NULL,
    source_url      TEXT,
    detected_at     TEXT     NOT NULL,
    resolved        INTEGER  DEFAULT 0,
    resolution_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_duplicity_alerts_aid ON duplicity_alerts(aid);

CREATE TABLE IF NOT EXISTS watcher_opt_out (
    aid TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS watcher_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO watcher_config (key, value) VALUES
    ('default_l2_url', 'https://watcher.grapeid.org/public/kel-digest'),
    ('watcher_hints', '[]');
`,
	},
	{
		Version:     13,
		Description: "KERI Witnesses: pool meta, KEL replicas, finalization",
		SQL: `
ALTER TABLE contacts ADD COLUMN contact_source TEXT NOT NULL DEFAULT 'manual';

CREATE TABLE IF NOT EXISTS witness_contact_meta (
    contact_aid       TEXT PRIMARY KEY,
    backend_type      TEXT NOT NULL DEFAULT '',
    witness_status    TEXT NOT NULL DEFAULT 'online',
    offline_count     INTEGER NOT NULL DEFAULT 0,
    is_mutual         INTEGER NOT NULL DEFAULT 0,
    is_commercial     INTEGER NOT NULL DEFAULT 0,
    enrolled_at       TEXT NOT NULL DEFAULT '',
    last_receipt_at   TEXT NOT NULL DEFAULT '',
    last_health_check TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS witness_kel_events (
    signer_aid    TEXT NOT NULL,
    sequence_num  INTEGER NOT NULL,
    event_json    TEXT NOT NULL,
    event_said    TEXT NOT NULL DEFAULT '',
    stored_at     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (signer_aid, sequence_num)
);

CREATE TABLE IF NOT EXISTS witness_receipts_issued (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    signer_aid      TEXT NOT NULL,
    event_said      TEXT NOT NULL,
    sequence_num    INTEGER NOT NULL,
    witness_aid     TEXT NOT NULL,
    receipt_json    TEXT NOT NULL,
    cesr_signature  TEXT NOT NULL DEFAULT '',
    issued_at       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS witness_finalization (
    event_said     TEXT PRIMARY KEY,
    signer_aid     TEXT NOT NULL,
    sequence_num   INTEGER NOT NULL,
    state          TEXT NOT NULL,
    receipt_count  INTEGER NOT NULL DEFAULT 0,
    threshold      INTEGER NOT NULL,
    started_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS witness_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS witness_self_heal_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_aid  TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);

INSERT OR IGNORE INTO witness_config (key, value) VALUES
    ('threshold', '5'),
    ('max_witnesses', '9'),
    ('target_contacts', '7'),
    ('backend_type', 'desktop');
`,
	},
	{
		Version:     14,
		Description: "URL relay allocations",
		SQL: `
CREATE TABLE IF NOT EXISTS relay_allocations (
    raid              TEXT PRIMARY KEY,
    public_url        TEXT NOT NULL,
    public_hostname   TEXT NOT NULL,
    allocation_token  TEXT NOT NULL,
    relay_provider    TEXT NOT NULL DEFAULT '',
    enrollment_aid    TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT ''
);
`,
	},
	{
		Version:     15,
		Description: "witness mutual enrollment: witnessing_for direction flag",
		SQL: `
ALTER TABLE witness_contact_meta ADD COLUMN witnessing_for INTEGER NOT NULL DEFAULT 0;
`,
	},
	{
		Version:     16,
		Description: "Contacts two-axis model + relationship_aid: add contact_category, relationship_aid; backfill from legacy contact_type; drop coworker",
		SQL: `
ALTER TABLE contacts ADD COLUMN contact_category TEXT NOT NULL DEFAULT '';
ALTER TABLE contacts ADD COLUMN relationship_aid TEXT NOT NULL DEFAULT '';
-- Backfill: legacy contact_type values become category (coworker -> professional per model cleanup)
UPDATE contacts SET contact_category = CASE
	WHEN contact_type = 'coworker' THEN 'professional'
	WHEN contact_type IN ('general','trusted','professional','transactional') THEN contact_type
	ELSE 'general'
END WHERE contact_category = '' OR contact_category IS NULL;
-- Ensure source has sane default if missing (added in prior migration as 'manual')
UPDATE contacts SET contact_source = 'manual' WHERE contact_source = '' OR contact_source IS NULL;
-- relationship_aid left empty here; generated on-demand or at next contact use (standalone icp)
CREATE INDEX IF NOT EXISTS idx_contacts_category ON contacts(contact_category);
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
