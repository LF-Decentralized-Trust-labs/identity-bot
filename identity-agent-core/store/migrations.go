package store

import (
	"database/sql"
	"fmt"
	"log"

	"identity-agent-core/actions"
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
    ('sa-credential-request', 'credential_request', 'Credential Request', 'Present a verifiable credential', 'verified_outlined', 0, 5, datetime('now'));
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
	{
		Version:     17,
		Description: "Add relationship_seed_b64 column for per-contact P-AID seeds (to support real engine-backed signing)",
		SQL: `
ALTER TABLE contacts ADD COLUMN relationship_seed_b64 TEXT NOT NULL DEFAULT '';
`,
	},
	{
		Version:     18,
		Description: "Add stable relationship_index column for HD pairwise key derivation (monotonic, persisted at creation for root+index recovery)",
		SQL: `
ALTER TABLE contacts ADD COLUMN relationship_index INTEGER NOT NULL DEFAULT 0;
-- Backfill sequential indices for any pre-existing contacts (order by discovery/aid)
WITH ordered AS (
  SELECT aid, (ROW_NUMBER() OVER (ORDER BY discovered_at, aid) - 1) AS idx
  FROM contacts
)
UPDATE contacts SET relationship_index = (SELECT idx FROM ordered o WHERE o.aid = contacts.aid)
WHERE relationship_index = 0;
`,
	},
	{
		Version:     19,
		Description: "Add relationship_counters table for true monotonic never-reused high-water-mark indices (survives deletes, separate namespaces for contacts vs login)",
		SQL: `
CREATE TABLE IF NOT EXISTS relationship_counters (
    namespace  TEXT PRIMARY KEY,
    next_index INTEGER NOT NULL DEFAULT 1
);
INSERT OR IGNORE INTO relationship_counters (namespace, next_index) VALUES ('contacts', 1);
INSERT OR IGNORE INTO relationship_counters (namespace, next_index) VALUES ('login', 1000001);
-- ensure counters are at least one past any backfilled indices
UPDATE relationship_counters SET next_index = (
  SELECT MAX(next_index, (SELECT COALESCE(MAX(relationship_index), 0) + 1 FROM contacts))
) WHERE namespace = 'contacts';
`,
	},
	{
		Version:     20,
		Description: "Profile: add organization fields (entity_type, org_name, org_type, jurisdiction) — previously accepted by the API but silently dropped",
		SQL: `
ALTER TABLE profile ADD COLUMN entity_type  TEXT NOT NULL DEFAULT '';
ALTER TABLE profile ADD COLUMN org_name     TEXT NOT NULL DEFAULT '';
ALTER TABLE profile ADD COLUMN org_type     TEXT NOT NULL DEFAULT '';
ALTER TABLE profile ADD COLUMN jurisdiction TEXT NOT NULL DEFAULT '';
`,
	},
	{
		Version:     21,
		Description: "Credential registries (TEL): credential_registries table + registry_said/iss_said on credentials for cryptographic revocation",
		SQL: `
CREATE TABLE IF NOT EXISTS credential_registries (
    registry_said TEXT PRIMARY KEY,
    issuer_aid    TEXT NOT NULL,
    vcp_json      TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_registry_issuer ON credential_registries(issuer_aid);
ALTER TABLE credentials ADD COLUMN registry_said TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN iss_said      TEXT NOT NULL DEFAULT '';
`,
	},
	{
		Version:     22,
		Description: "Endpoint records: signed statements of where an identity currently is, held by its witnesses so a counterparty holding a dead address has somewhere stable to ask",
		SQL: `
CREATE TABLE IF NOT EXISTS endpoint_records (
    said        TEXT PRIMARY KEY,
    cid         TEXT NOT NULL,
    eid         TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT '',
    scheme      TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    route       TEXT NOT NULL,
    record_json TEXT NOT NULL,
    signature   TEXT NOT NULL DEFAULT '',
    stamp       TEXT NOT NULL DEFAULT '',
    received_at TEXT NOT NULL DEFAULT ''
);
-- Lookups are always "where is this identity now", so the controller leads.
CREATE INDEX IF NOT EXISTS idx_endpoint_cid ON endpoint_records(cid, route);
`,
	},
	{
		Version:     23,
		Description: "Drop an internal contract name that was leaking into a user-visible label",
		SQL: `
-- This subtitle is shown to people. It carried an internal identifier that
-- means nothing outside our own planning documents, so it said less than the
-- same sentence without it. Fixed in the seed too, for databases created after
-- this; the update is for those created before.
UPDATE share_actions
   SET subtitle = 'Present a verifiable credential'
 WHERE action_key = 'credential_request'
   AND subtitle LIKE '%SEAM-7%';
`,
	},
	{
		Version:     24,
		Description: "Signing requests: things only the device holding the keys can sign, waiting for it to be opened",
		SQL: `
CREATE TABLE IF NOT EXISTS signing_requests (
    id               TEXT PRIMARY KEY,
    aid              TEXT NOT NULL,
    kind             TEXT NOT NULL,
    summary          TEXT NOT NULL DEFAULT '',
    detail           TEXT NOT NULL DEFAULT '',
    payload_b64      TEXT NOT NULL,
    -- How this is put to the person: consent | notify | automatic.
    -- Not a boolean, because "must decide", "just tap" and "do not ask at all"
    -- are three different things and collapsing any two loses the distinction
    -- that matters.
    presentation     TEXT NOT NULL DEFAULT 'notify',
    status           TEXT NOT NULL DEFAULT 'pending',
    signature        TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT '',
    resolved_at      TEXT NOT NULL DEFAULT '',
    expires_at       TEXT NOT NULL DEFAULT ''
);
-- The only question asked of this table is "what is still waiting", oldest
-- first, so that is what is indexed.
CREATE INDEX IF NOT EXISTS idx_signing_pending ON signing_requests(status, created_at);
`},
	{
		Version:     25,
		Description: "Notifications: things another agent told this one, waiting to be read",
		SQL: `
CREATE TABLE IF NOT EXISTS notifications (
    id           TEXT PRIMARY KEY,
    -- Who said it, and which of our identifiers they said it to. Both are the
    -- authenticated envelope headers, never a field from inside the message: a
    -- sender that could name itself could impersonate anyone.
    from_aid     TEXT NOT NULL DEFAULT '',
    to_aid       TEXT NOT NULL DEFAULT '',
    -- What sort of thing this is, in the sender's vocabulary. The core does not
    -- interpret it; it exists so a client can group and filter.
    kind         TEXT NOT NULL DEFAULT '',
    -- info | warning | critical. How loudly to say it, decided by the sender
    -- because only the sender knows whether this is a receipt or a deadline.
    severity     TEXT NOT NULL DEFAULT 'info',
    title        TEXT NOT NULL DEFAULT '',
    body         TEXT NOT NULL DEFAULT '',
    -- The original message, verbatim, for anything that wants more than the
    -- text. Opaque here on purpose: a core that parsed it would have to know
    -- what every sender means.
    payload      TEXT NOT NULL DEFAULT '',
    -- unread | read | dismissed. Three states rather than a boolean, because
    -- "I have seen this" and "stop showing me this" are different intentions
    -- and collapsing them loses the one that matters.
    status       TEXT NOT NULL DEFAULT 'unread',
    -- Whether the envelope's signature verified. Always 1 for anything stored
    -- through the inbound path, which refuses everything else; recorded rather
    -- than assumed so an unverified row is visibly unverified.
    verified     INTEGER NOT NULL DEFAULT 0,
    received_at  TEXT NOT NULL DEFAULT '',
    read_at      TEXT NOT NULL DEFAULT '',
    expires_at   TEXT NOT NULL DEFAULT ''
);
-- Two questions get asked: "what is waiting for me", newest first, and "show me
-- everything from this agent".
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(status, received_at);
CREATE INDEX IF NOT EXISTS idx_notifications_from ON notifications(from_aid);
`},
	{
		Version:     26,
		Description: "Record where an identity's keys were derived from, so it can rotate at all",
		SQL: `
-- Without these an identity created from a derived seed cannot ROTATE. A
-- rotation must carry the key the previous event committed to, and that key
-- comes from the root seed at a particular index — so an agent that recorded
-- the AID and forgot the index has an identity whose keys it can never change.
--
-- derivation_index is the branch; key_generation is how far along it the
-- identity is. Inception is generation 0: current key at key-index 0, committed
-- successor at 1. Each rotation advances both by one.
ALTER TABLE identity ADD COLUMN derivation_index INTEGER NOT NULL DEFAULT 0;
ALTER TABLE identity ADD COLUMN key_generation INTEGER NOT NULL DEFAULT 0;

-- Collapse the table to its oldest row, which is the one every read has been
-- returning. The table has no primary key, so every SaveIdentity inserted
-- instead of updating and the later rows were never read by anything. Keeping
-- them would mean the row writes now pin to is not the row reads returned.
DELETE FROM identity WHERE rowid NOT IN (SELECT MIN(rowid) FROM identity);
UPDATE identity SET rowid = 1 WHERE rowid = (SELECT MIN(rowid) FROM identity);
`},
	{
		Version:     27,
		Description: "Keep the bytes KERI serialised a key event as",
		SQL: `
-- event_json is not what KERI signed. A KERI event is ordered — the version
-- string comes first and states the length — and an event that has been through
-- any JSON encoder here comes back with its keys in alphabetical order, which
-- puts the version string last and makes its stated length wrong.
--
-- So the bytes a signature covers, and the bytes an event's own digest is taken
-- over, were produced at inception, handed out to be signed, and then dropped.
-- Without them a signature cannot be checked against the event it covers, and
-- the identifier an event claims for itself can be read but never verified.
--
-- Empty on events written before this. Those are rebuilt from the protocol's
-- own field order, which works and depends on every field being one the schema
-- defines — so the bytes are kept from here on rather than reconstructed.
ALTER TABLE kel ADD COLUMN raw_bytes_b64 TEXT NOT NULL DEFAULT '';

-- One row per event, which was never enforced.
--
-- Saving an event always INSERTed, so writing the same event twice left two
-- rows. Reads return every row ordered by sequence number, so a duplicate makes
-- a key history contain the same event twice — and a history whose sequence
-- numbers do not increase by one fails its own chain check. The identity then
-- appears corrupt to everybody including itself.
--
-- The newest row per event wins: a later write carries later information, and
-- the case that produced duplicates is exactly a second write adding something
-- the first lacked.
DELETE FROM kel WHERE id NOT IN (
    SELECT MAX(id) FROM kel GROUP BY aid, seq_num
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_kel_aid_seq_unique ON kel(aid, seq_num);
`},
	{
		Version:     28,
		Description: "Let a witness keep what it needs to verify an event, instead of receipting it unchecked",
		SQL: `
-- A witness receipt is meant to be third-party evidence that a named controller
-- published a specific event. It could not be that: the event arrived parsed,
-- with no controller signature anywhere on the wire, and was re-encoded before
-- storage — which sorts the fields and destroys the byte sequence the digest and
-- the signature are over. So the witness could not check who authorised what it
-- was attesting to, and could not check later either.
--
-- raw_bytes_b64 is the event exactly as published; cesr_signature is the
-- controller's signature over those bytes. Empty on rows written before this,
-- which are readable and were never verifiable.
ALTER TABLE witness_kel_events ADD COLUMN raw_bytes_b64 TEXT NOT NULL DEFAULT '';
ALTER TABLE witness_kel_events ADD COLUMN cesr_signature TEXT NOT NULL DEFAULT '';
`},
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

	// Seed share_actions from the canonical action registry. Runs after
	// migrations so the table exists; non-destructive (see seedShareActionsFromRegistry).
	if err := seedShareActionsFromRegistry(db); err != nil {
		return fmt.Errorf("failed to seed share actions from registry: %w", err)
	}

	return nil
}

// seedShareActionsFromRegistry inserts any share-menu actions declared in the
// canonical action registry (actions/registry.json) that are not already present
// in share_actions. INSERT OR IGNORE (keyed on action_key) keeps it
// non-destructive: existing rows and any runtime edits (enable/disable,
// Data-Manager changes) are preserved; only missing actions are added. This makes
// "add a share action" a registry change rather than a code change. Actions
// without an assigned wire code yet (e.g. legacy UI placeholders seeded by an
// earlier migration) simply stay as they are until they gain a registry entry.
func seedShareActionsFromRegistry(db *sql.DB) error {
	reg, err := actions.Load()
	if err != nil {
		return err
	}
	for _, a := range reg.ShareMenuActions() {
		enabled := 0
		if a.UI.Enabled {
			enabled = 1
		}
		if _, err := db.Exec(
			`INSERT OR IGNORE INTO share_actions
			   (id, action_key, name, subtitle, icon, is_enabled, sort_order, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			"sa-"+a.Key, a.Key, a.Name, a.UI.Subtitle, a.UI.Icon, enabled, a.UI.SortOrder,
		); err != nil {
			return fmt.Errorf("seed share action %q: %w", a.Key, err)
		}
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
