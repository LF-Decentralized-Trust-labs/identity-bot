package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using SQLite (identity.db).
// It is the Identity Core domain — the most sensitive data store.
// No sandboxed app can access this database directly.
type SQLiteStore struct {
	db  *sql.DB
	dir string
}

// NewSQLiteStore opens (or creates) identity.db in the given data directory,
// applies schema migrations, and migrates any existing JSON FileStore data.
func NewSQLiteStore(dir string) (*SQLiteStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	dbPath := filepath.Join(dir, "identity.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open identity.db: %w", err)
	}

	// WAL mode + settings — same pattern as sandbox/store.go
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma (%s): %w", p, err)
		}
	}

	s := &SQLiteStore{db: db, dir: dir}

	if err := ApplyIdentityMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to apply identity migrations: %w", err)
	}

	log.Printf("[store] Initialized SQLite identity store at: %s", dbPath)
	return s, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// DB exposes the underlying SQLite handle for domain packages (e.g. watcher).
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// ── Events / KEL ─────────────────────────────────────────────────────────────

func (s *SQLiteStore) SaveEvent(record EventRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO kel (aid, seq_num, event_type, event_json, public_key, next_key_digest, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		record.AID, record.SequenceNumber, record.EventType, record.EventJSON,
		record.PublicKey, record.NextKeyDigest, record.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("failed to save KEL event: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetEvents(aid string) ([]EventRecord, error) {
	rows, err := s.db.Query(
		`SELECT aid, seq_num, event_type, event_json, public_key, next_key_digest, timestamp
		 FROM kel WHERE aid = ? ORDER BY seq_num ASC`, aid)
	if err != nil {
		return nil, fmt.Errorf("failed to query KEL: %w", err)
	}
	defer rows.Close()

	var events []EventRecord
	for rows.Next() {
		var e EventRecord
		if err := rows.Scan(&e.AID, &e.SequenceNumber, &e.EventType, &e.EventJSON,
			&e.PublicKey, &e.NextKeyDigest, &e.Timestamp); err != nil {
			return nil, fmt.Errorf("failed to scan KEL row: %w", err)
		}
		events = append(events, e)
	}
	if events == nil {
		events = []EventRecord{}
	}
	return events, nil
}

// ── Identity ──────────────────────────────────────────────────────────────────

func (s *SQLiteStore) GetIdentity() (*IdentityState, error) {
	var state IdentityState
	err := s.db.QueryRow(
		`SELECT aid, public_key, next_key_digest, created, event_count FROM identity LIMIT 1`,
	).Scan(&state.AID, &state.PublicKey, &state.NextKeyDigest, &state.Created, &state.EventCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}
	return &state, nil
}

func (s *SQLiteStore) SaveIdentity(state IdentityState) error {
	_, err := s.db.Exec(`
		INSERT INTO identity (aid, public_key, next_key_digest, created, event_count)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(rowid) DO UPDATE SET
			aid = excluded.aid,
			public_key = excluded.public_key,
			next_key_digest = excluded.next_key_digest,
			created = excluded.created,
			event_count = excluded.event_count`,
		state.AID, state.PublicKey, state.NextKeyDigest, state.Created, state.EventCount,
	)
	if err != nil {
		return fmt.Errorf("failed to save identity: %w", err)
	}
	return nil
}

// ── Contacts ─────────────────────────────────────────────────────────────────

func (s *SQLiteStore) SaveContact(contact ContactRecord) error {
	jcardJSON := ""
	if contact.JCard != nil {
		b, err := json.Marshal(contact.JCard)
		if err != nil {
			return fmt.Errorf("failed to marshal jcard: %w", err)
		}
		jcardJSON = string(b)
	}
	if contact.ContactSource == "" {
		contact.ContactSource = "manual"
	}
	if contact.ContactCategory == "" {
		// migrate legacy or default
		contact.ContactCategory = "general"
	}
	// relationship_aid may be empty; caller (or add-contact path) populates with a per-contact standalone P-AID
	// Security: never persist raw private seeds in the main store column (use secureenclave storage keyed by AID).
	if contact.RelationshipSeedB64 != "" {
		contact.RelationshipSeedB64 = ""
	}

	// Allocate via persisted monotonic counter (never reuses even after deletes).
	if contact.RelationshipIndex == 0 {
		idx, err := s.AllocateNextRelationshipIndex("contacts")
		if err != nil {
			return fmt.Errorf("allocate relationship index: %w", err)
		}
		contact.RelationshipIndex = idx
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO contacts (aid, alias, public_key, oobi_url, verified, discovered_at, status, contact_source, contact_category, relationship_aid, relationship_index, relationship_seed_b64, is_witness, jcard_json, photo, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(aid) DO UPDATE SET
			alias               = excluded.alias,
			public_key          = excluded.public_key,
			oobi_url            = excluded.oobi_url,
			verified            = excluded.verified,
			status              = excluded.status,
			contact_source      = excluded.contact_source,
			contact_category    = excluded.contact_category,
			relationship_aid    = excluded.relationship_aid,
			relationship_index  = excluded.relationship_index,
			relationship_seed_b64 = excluded.relationship_seed_b64,
			is_witness          = excluded.is_witness,
			jcard_json          = excluded.jcard_json,
			photo               = excluded.photo,
			updated_at          = excluded.updated_at`,
		contact.AID, contact.Alias, contact.PublicKey, contact.OobiURL,
		contact.Verified, contact.DiscoveredAt, contact.Status,
		contact.ContactSource, contact.ContactCategory, contact.RelationshipAID, contact.RelationshipIndex, contact.RelationshipSeedB64, contact.IsWitness,
		jcardJSON, contact.Photo, now,
	)
	if err != nil {
		return fmt.Errorf("failed to save contact: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetContacts() ([]ContactRecord, error) {
	rows, err := s.db.Query(
		`SELECT aid, alias, public_key, oobi_url, verified, discovered_at, status, contact_source, contact_category, relationship_aid, relationship_index, relationship_seed_b64, is_witness, jcard_json, photo
		 FROM contacts ORDER BY alias ASC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query contacts: %w", err)
	}
	defer rows.Close()
	return s.scanContacts(rows)
}

func (s *SQLiteStore) GetContact(aid string) (*ContactRecord, error) {
	rows, err := s.db.Query(
		`SELECT aid, alias, public_key, oobi_url, verified, discovered_at, status, contact_source, contact_category, relationship_aid, relationship_index, relationship_seed_b64, is_witness, jcard_json, photo
		 FROM contacts WHERE aid = ?`, aid)
	if err != nil {
		return nil, fmt.Errorf("failed to query contact: %w", err)
	}
	defer rows.Close()

	contacts, err := s.scanContacts(rows)
	if err != nil {
		return nil, err
	}
	if len(contacts) == 0 {
		return nil, nil
	}
	return &contacts[0], nil
}

func (s *SQLiteStore) DeleteContact(aid string) error {
	_, err := s.db.Exec(`DELETE FROM contacts WHERE aid = ?`, aid)
	if err != nil {
		return fmt.Errorf("failed to delete contact: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetContactsByStatus(status string) ([]ContactRecord, error) {
	rows, err := s.db.Query(
		`SELECT aid, alias, public_key, oobi_url, verified, discovered_at, status, contact_source, contact_category, relationship_aid, relationship_index, relationship_seed_b64, is_witness, jcard_json, photo
		 FROM contacts WHERE status = ? ORDER BY alias ASC`, status)
	if err != nil {
		return nil, fmt.Errorf("failed to query contacts by status: %w", err)
	}
	defer rows.Close()
	return s.scanContacts(rows)
}

func (s *SQLiteStore) scanContacts(rows *sql.Rows) ([]ContactRecord, error) {
	var contacts []ContactRecord
	for rows.Next() {
		var c ContactRecord
		var jcardJSON string
		if err := rows.Scan(&c.AID, &c.Alias, &c.PublicKey, &c.OobiURL,
			&c.Verified, &c.DiscoveredAt, &c.Status, &c.ContactSource, &c.ContactCategory, &c.RelationshipAID, &c.RelationshipIndex, &c.RelationshipSeedB64, &c.IsWitness,
			&jcardJSON, &c.Photo); err != nil {
			return nil, fmt.Errorf("failed to scan contact: %w", err)
		}
		if jcardJSON != "" {
			var jcard JCard
			if err := json.Unmarshal([]byte(jcardJSON), &jcard); err == nil {
				c.JCard = &jcard
			}
		}
		contacts = append(contacts, c)
	}
	if contacts == nil {
		contacts = []ContactRecord{}
	}
	return contacts, nil
}

// ── Tasks ─────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) SaveTask(task TaskRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if task.CreatedAt == "" {
		task.CreatedAt = now
	}
	task.UpdatedAt = now
	_, err := s.db.Exec(`
		INSERT INTO tasks (id, type, status, contact_aid, progress, detail, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			status      = excluded.status,
			contact_aid = excluded.contact_aid,
			progress    = excluded.progress,
			detail      = excluded.detail,
			updated_at  = excluded.updated_at`,
		task.ID, task.Type, task.Status, task.ContactAID,
		task.Progress, task.Detail, task.CreatedAt, task.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save task: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetTasks() ([]TaskRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, type, status, contact_aid, progress, detail, created_at, updated_at
		 FROM tasks ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query tasks: %w", err)
	}
	defer rows.Close()
	return s.scanTasks(rows)
}

func (s *SQLiteStore) GetTask(id string) (*TaskRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, type, status, contact_aid, progress, detail, created_at, updated_at
		 FROM tasks WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("failed to query task: %w", err)
	}
	defer rows.Close()
	tasks, err := s.scanTasks(rows)
	if err != nil {
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, nil
	}
	return &tasks[0], nil
}

func (s *SQLiteStore) DeleteTask(id string) error {
	_, err := s.db.Exec(`DELETE FROM tasks WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete task: %w", err)
	}
	return nil
}

func (s *SQLiteStore) scanTasks(rows *sql.Rows) ([]TaskRecord, error) {
	var tasks []TaskRecord
	for rows.Next() {
		var t TaskRecord
		if err := rows.Scan(&t.ID, &t.Type, &t.Status, &t.ContactAID,
			&t.Progress, &t.Detail, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan task: %w", err)
		}
		tasks = append(tasks, t)
	}
	if tasks == nil {
		tasks = []TaskRecord{}
	}
	return tasks, nil
}

// ── Share Actions ─────────────────────────────────────────────────────────────

func (s *SQLiteStore) GetShareActions() ([]ShareAction, error) {
	rows, err := s.db.Query(
		`SELECT id, action_key, name, subtitle, icon, is_enabled, sort_order, updated_at
		 FROM share_actions ORDER BY sort_order ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query share_actions: %w", err)
	}
	defer rows.Close()
	return s.scanShareActions(rows)
}

func (s *SQLiteStore) GetShareAction(id string) (*ShareAction, error) {
	rows, err := s.db.Query(
		`SELECT id, action_key, name, subtitle, icon, is_enabled, sort_order, updated_at
		 FROM share_actions WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("failed to query share_action: %w", err)
	}
	defer rows.Close()
	actions, err := s.scanShareActions(rows)
	if err != nil {
		return nil, err
	}
	if len(actions) == 0 {
		return nil, nil
	}
	return &actions[0], nil
}

func (s *SQLiteStore) UpsertShareAction(action ShareAction) error {
	if action.UpdatedAt == "" {
		action.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	isEnabled := 0
	if action.IsEnabled {
		isEnabled = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO share_actions (id, action_key, name, subtitle, icon, is_enabled, sort_order, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			action_key = excluded.action_key,
			name       = excluded.name,
			subtitle   = excluded.subtitle,
			icon       = excluded.icon,
			is_enabled = excluded.is_enabled,
			sort_order = excluded.sort_order,
			updated_at = excluded.updated_at`,
		action.ID, action.ActionKey, action.Name, action.Subtitle,
		action.Icon, isEnabled, action.SortOrder, action.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert share_action: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteShareAction(id string) error {
	_, err := s.db.Exec(`DELETE FROM share_actions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete share_action: %w", err)
	}
	return nil
}

func (s *SQLiteStore) scanShareActions(rows *sql.Rows) ([]ShareAction, error) {
	var actions []ShareAction
	for rows.Next() {
		var a ShareAction
		var isEnabled int
		if err := rows.Scan(&a.ID, &a.ActionKey, &a.Name, &a.Subtitle,
			&a.Icon, &isEnabled, &a.SortOrder, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan share_action: %w", err)
		}
		a.IsEnabled = isEnabled == 1
		actions = append(actions, a)
	}
	if actions == nil {
		actions = []ShareAction{}
	}
	return actions, nil
}

// ── Settings ─────────────────────────────────────────────────────────────────

func (s *SQLiteStore) GetSettings() (*SettingsData, error) {
	var settings SettingsData
	err := s.db.QueryRow(
		`SELECT tunnel_provider, ngrok_auth_token, cloudflare_tunnel_token, tunnel_domain, tunnel_extension
		 FROM settings LIMIT 1`,
	).Scan(&settings.TunnelProvider, &settings.NgrokAuthToken,
		&settings.CloudflareTunnelToken, &settings.TunnelDomain, &settings.TunnelExtension)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}
	return &settings, nil
}

// SaveSettings persists the single settings row. The table holds at most one row
// (GetSettings reads LIMIT 1); we replace it in a transaction rather than relying
// on an upsert. The previous `ON CONFLICT(rowid)` target is not a valid conflict
// target on this PK-less table, so writes silently never persisted — which is why
// tunnel provider/token settings were lost on restart.
func (s *SQLiteStore) SaveSettings(settings SettingsData) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin settings tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM settings`); err != nil {
		return fmt.Errorf("failed to clear settings: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO settings (tunnel_provider, ngrok_auth_token, cloudflare_tunnel_token, tunnel_domain, tunnel_extension)
		 VALUES (?, ?, ?, ?, ?)`,
		settings.TunnelProvider, settings.NgrokAuthToken,
		settings.CloudflareTunnelToken, settings.TunnelDomain, settings.TunnelExtension,
	); err != nil {
		return fmt.Errorf("failed to save settings: %w", err)
	}
	return tx.Commit()
}

// ── Pending Requests ──────────────────────────────────────────────────────────

func (s *SQLiteStore) SavePendingRequest(req PendingRequest) error {
	jcardJSON := ""
	if req.JCard != nil {
		b, err := json.Marshal(req.JCard)
		if err != nil {
			return fmt.Errorf("failed to marshal jcard: %w", err)
		}
		jcardJSON = string(b)
	}

	_, err := s.db.Exec(`
		INSERT INTO pending_requests (aid, alias, public_key, oobi_url, received_at, expires_at, error_reason, jcard_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(aid) DO UPDATE SET
			alias = excluded.alias,
			public_key = excluded.public_key,
			oobi_url = excluded.oobi_url,
			received_at = excluded.received_at,
			expires_at = excluded.expires_at,
			error_reason = excluded.error_reason,
			jcard_json = excluded.jcard_json`,
		req.AID, req.Alias, req.PublicKey, req.OobiURL,
		req.ReceivedAt, req.ExpiresAt, req.ErrorReason, jcardJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to save pending request: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetPendingRequests() ([]PendingRequest, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Auto-delete expired requests
	if _, err := s.db.Exec(`DELETE FROM pending_requests WHERE expires_at != '' AND expires_at < ?`, now); err != nil {
		log.Printf("[store] Warning: failed to prune expired pending requests: %v", err)
	}

	rows, err := s.db.Query(
		`SELECT aid, alias, public_key, oobi_url, received_at, expires_at, error_reason, jcard_json
		 FROM pending_requests ORDER BY received_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending requests: %w", err)
	}
	defer rows.Close()

	var requests []PendingRequest
	for rows.Next() {
		var r PendingRequest
		var jcardJSON string
		if err := rows.Scan(&r.AID, &r.Alias, &r.PublicKey, &r.OobiURL,
			&r.ReceivedAt, &r.ExpiresAt, &r.ErrorReason, &jcardJSON); err != nil {
			return nil, fmt.Errorf("failed to scan pending request: %w", err)
		}
		if jcardJSON != "" {
			var jcard JCard
			if err := json.Unmarshal([]byte(jcardJSON), &jcard); err == nil {
				r.JCard = &jcard
			}
		}
		requests = append(requests, r)
	}
	if requests == nil {
		requests = []PendingRequest{}
	}
	return requests, nil
}

func (s *SQLiteStore) DeletePendingRequest(aid string) error {
	_, err := s.db.Exec(`DELETE FROM pending_requests WHERE aid = ?`, aid)
	if err != nil {
		return fmt.Errorf("failed to delete pending request: %w", err)
	}
	return nil
}

// ── Profile ───────────────────────────────────────────────────────────────────

func (s *SQLiteStore) GetProfile() (*ProfileData, error) {
	var profile ProfileData
	err := s.db.QueryRow(
		`SELECT full_name, family_name, given_name, org, title, email, tel, note, photo, uid
		 FROM profile LIMIT 1`,
	).Scan(&profile.FullName, &profile.FamilyName, &profile.GivenName, &profile.Org,
		&profile.Title, &profile.Email, &profile.Tel, &profile.Note, &profile.Photo, &profile.UID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}
	return &profile, nil
}

func (s *SQLiteStore) SaveProfile(profile ProfileData) error {
	_, err := s.db.Exec(`
		INSERT INTO profile (full_name, family_name, given_name, org, title, email, tel, note, photo, uid)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(rowid) DO UPDATE SET
			full_name = excluded.full_name,
			family_name = excluded.family_name,
			given_name = excluded.given_name,
			org = excluded.org,
			title = excluded.title,
			email = excluded.email,
			tel = excluded.tel,
			note = excluded.note,
			photo = excluded.photo,
			uid = excluded.uid`,
		profile.FullName, profile.FamilyName, profile.GivenName, profile.Org,
		profile.Title, profile.Email, profile.Tel, profile.Note, profile.Photo, profile.UID,
	)
	if err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}
	return nil
}

// ── Presentations ─────────────────────────────────────────────────────────────

func (s *SQLiteStore) SavePresentation(record PresentationRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO presentations (said, credential_said, holder_aid, issuer_aid, presentation_json_b64, cesr_signature, created_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(said) DO UPDATE SET
			cesr_signature = excluded.cesr_signature,
			status         = excluded.status`,
		record.SAID, record.CredentialSAID, record.HolderAID, record.IssuerAID,
		record.PresentationJsonB64, record.CesrSignature, record.CreatedAt, record.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to save presentation: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetPresentation(said string) (*PresentationRecord, error) {
	var r PresentationRecord
	err := s.db.QueryRow(
		`SELECT said, credential_said, holder_aid, issuer_aid, presentation_json_b64, cesr_signature, created_at, status
		 FROM presentations WHERE said = ?`, said,
	).Scan(&r.SAID, &r.CredentialSAID, &r.HolderAID, &r.IssuerAID,
		&r.PresentationJsonB64, &r.CesrSignature, &r.CreatedAt, &r.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get presentation: %w", err)
	}
	return &r, nil
}

func (s *SQLiteStore) GetPresentations() ([]PresentationRecord, error) {
	rows, err := s.db.Query(
		`SELECT said, credential_said, holder_aid, issuer_aid, presentation_json_b64, cesr_signature, created_at, status
		 FROM presentations ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query presentations: %w", err)
	}
	defer rows.Close()

	var pres []PresentationRecord
	for rows.Next() {
		var r PresentationRecord
		if err := rows.Scan(&r.SAID, &r.CredentialSAID, &r.HolderAID, &r.IssuerAID,
			&r.PresentationJsonB64, &r.CesrSignature, &r.CreatedAt, &r.Status); err != nil {
			return nil, fmt.Errorf("failed to scan presentation: %w", err)
		}
		pres = append(pres, r)
	}
	if pres == nil {
		pres = []PresentationRecord{}
	}
	return pres, nil
}

// ── Credentials ───────────────────────────────────────────────────────────────

const credentialCols = `said, issuer_aid, holder_aid, schema_said, acdc_json, ixn_said, cesr_signature, issued_at, status, format, credential_type, issuer_name, issuer_logo_url, expiry_date, raw_json`

func scanCredentialRow(row interface{ Scan(dest ...any) error }) (CredentialRecord, error) {
	var r CredentialRecord
	err := row.Scan(
		&r.SAID, &r.IssuerAID, &r.HolderAID, &r.SchemaSAID,
		&r.AcdcJson, &r.IxnSAID, &r.CesrSignature, &r.IssuedAt, &r.Status,
		&r.Format, &r.CredentialType, &r.IssuerName, &r.IssuerLogoURL, &r.ExpiryDate, &r.RawJson,
	)
	return r, err
}

func (s *SQLiteStore) SaveCredential(record CredentialRecord) error {
	if record.Format == "" {
		record.Format = "acdc"
	}
	_, err := s.db.Exec(`
		INSERT INTO credentials (`+credentialCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(said) DO UPDATE SET
			cesr_signature  = excluded.cesr_signature,
			status          = excluded.status,
			format          = excluded.format,
			credential_type = excluded.credential_type,
			issuer_name     = excluded.issuer_name,
			issuer_logo_url = excluded.issuer_logo_url,
			expiry_date     = excluded.expiry_date,
			raw_json        = excluded.raw_json`,
		record.SAID, record.IssuerAID, record.HolderAID, record.SchemaSAID,
		record.AcdcJson, record.IxnSAID, record.CesrSignature, record.IssuedAt, record.Status,
		record.Format, record.CredentialType, record.IssuerName, record.IssuerLogoURL, record.ExpiryDate, record.RawJson,
	)
	if err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetCredential(said string) (*CredentialRecord, error) {
	r, err := scanCredentialRow(s.db.QueryRow(
		`SELECT `+credentialCols+` FROM credentials WHERE said = ?`, said,
	))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return &r, nil
}

func (s *SQLiteStore) GetCredentials() ([]CredentialRecord, error) {
	return s.GetCredentialsFiltered("", "")
}

func (s *SQLiteStore) GetCredentialsFiltered(role, status string) ([]CredentialRecord, error) {
	identity, _ := s.GetIdentity()
	myAID := ""
	if identity != nil {
		myAID = identity.AID
	}

	query := `SELECT ` + credentialCols + ` FROM credentials WHERE 1=1`
	args := []any{}

	if role == "holder" && myAID != "" {
		query += ` AND holder_aid = ?`
		args = append(args, myAID)
	} else if role == "issuer" && myAID != "" {
		query += ` AND issuer_aid = ?`
		args = append(args, myAID)
	}

	if status == "expired" {
		query += ` AND expiry_date != '' AND expiry_date < datetime('now')`
	} else if status == "valid" {
		query += ` AND (expiry_date = '' OR expiry_date >= datetime('now'))`
	}

	if status != "expired" {
		// default excludes fully expired unless explicitly asked
	}

	query += ` ORDER BY issued_at DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}
	defer rows.Close()

	var creds []CredentialRecord
	for rows.Next() {
		r, err := scanCredentialRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}
		creds = append(creds, r)
	}
	if creds == nil {
		creds = []CredentialRecord{}
	}
	return creds, nil
}

func (s *SQLiteStore) UpdateCredentialStatus(said, status string) error {
	_, err := s.db.Exec(`UPDATE credentials SET status = ? WHERE said = ?`, status, said)
	if err != nil {
		return fmt.Errorf("failed to update credential status: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteCredential(said string) error {
	_, err := s.db.Exec(`DELETE FROM credentials WHERE said = ?`, said)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}
	return nil
}

func (s *SQLiteStore) SaveCredentialSchema(record CredentialSchemaRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO credential_schemas (said, schema_json, fetched_at)
		VALUES (?, ?, ?)
		ON CONFLICT(said) DO UPDATE SET
			schema_json = excluded.schema_json,
			fetched_at  = excluded.fetched_at`,
		record.SAID, record.SchemaJson, record.FetchedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save credential schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetCredentialSchemas() ([]CredentialSchemaRecord, error) {
	rows, err := s.db.Query(`SELECT said, schema_json, fetched_at FROM credential_schemas ORDER BY fetched_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query credential schemas: %w", err)
	}
	defer rows.Close()

	var schemas []CredentialSchemaRecord
	for rows.Next() {
		var r CredentialSchemaRecord
		if err := rows.Scan(&r.SAID, &r.SchemaJson, &r.FetchedAt); err != nil {
			return nil, fmt.Errorf("failed to scan credential schema: %w", err)
		}
		schemas = append(schemas, r)
	}
	if schemas == nil {
		schemas = []CredentialSchemaRecord{}
	}
	return schemas, nil
}

func (s *SQLiteStore) GetCredentialSchema(said string) (*CredentialSchemaRecord, error) {
	var r CredentialSchemaRecord
	err := s.db.QueryRow(
		`SELECT said, schema_json, fetched_at FROM credential_schemas WHERE said = ?`, said,
	).Scan(&r.SAID, &r.SchemaJson, &r.FetchedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get credential schema: %w", err)
	}
	return &r, nil
}

// ── Contact KELs ──────────────────────────────────────────────────────────────

func (s *SQLiteStore) SaveContactKEL(record ContactKELRecord) error {
	kelJSON, err := json.Marshal(record.KEL)
	if err != nil {
		return fmt.Errorf("failed to marshal contact KEL: %w", err)
	}
	errorsJSON, err := json.Marshal(record.ValidationErrors)
	if err != nil {
		return fmt.Errorf("failed to marshal validation errors: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO contact_kels (aid, kel_json, kel_verified, current_public_key, events_validated, validation_errors, validated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(aid) DO UPDATE SET
			kel_json           = excluded.kel_json,
			kel_verified       = excluded.kel_verified,
			current_public_key = excluded.current_public_key,
			events_validated   = excluded.events_validated,
			validation_errors  = excluded.validation_errors,
			validated_at       = excluded.validated_at`,
		record.AID, string(kelJSON), record.KelVerified,
		record.CurrentPublicKey, record.EventsValidated,
		string(errorsJSON), record.ValidatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save contact KEL: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetContactKEL(aid string) (*ContactKELRecord, error) {
	var r ContactKELRecord
	var kelJSON, errorsJSON string
	err := s.db.QueryRow(
		`SELECT aid, kel_json, kel_verified, current_public_key, events_validated, validation_errors, validated_at
		 FROM contact_kels WHERE aid = ?`, aid,
	).Scan(&r.AID, &kelJSON, &r.KelVerified, &r.CurrentPublicKey, &r.EventsValidated, &errorsJSON, &r.ValidatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get contact KEL: %w", err)
	}
	if err := json.Unmarshal([]byte(kelJSON), &r.KEL); err != nil {
		return nil, fmt.Errorf("failed to parse contact KEL JSON: %w", err)
	}
	if errorsJSON != "" && errorsJSON != "null" {
		if err := json.Unmarshal([]byte(errorsJSON), &r.ValidationErrors); err != nil {
			return nil, fmt.Errorf("failed to parse validation errors JSON: %w", err)
		}
	}
	return &r, nil
}

// ── Endpoint ──────────────────────────────────────────────────────────────────

// GetEndpoint returns the last persisted public OOBI endpoint URL and its source.
// Returns empty strings if no endpoint has been saved yet.
func (s *SQLiteStore) GetEndpoint() (url, source string, err error) {
	e := s.db.QueryRow(`SELECT url, source FROM endpoint LIMIT 1`)
	err = e.Scan(&url, &source)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return url, source, err
}

// SaveEndpoint persists the current public OOBI endpoint URL.
func (s *SQLiteStore) SaveEndpoint(url, source string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO endpoint (url, source, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(rowid) DO UPDATE SET
			url        = excluded.url,
			source     = excluded.source,
			updated_at = excluded.updated_at`,
		url, source, now,
	)
	return err
}

// ── Witness Receipts (KERL Phase 7) ───────────────────────────────────────────

func (s *SQLiteStore) SaveWitnessReceipt(record WitnessReceiptRecord) error {
	if record.ReceivedAt == "" {
		record.ReceivedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(`
		INSERT INTO witness_receipts (event_said, witness_aid, cesr_signature, received_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(event_said, witness_aid) DO NOTHING`,
		record.EventSAID, record.WitnessAID, record.CesrSignature, record.ReceivedAt,
	)
	return err
}

func (s *SQLiteStore) GetWitnessReceipts(eventSAID string) ([]WitnessReceiptRecord, error) {
	rows, err := s.db.Query(
		`SELECT event_said, witness_aid, cesr_signature, received_at
		 FROM witness_receipts WHERE event_said = ? ORDER BY id ASC`, eventSAID)
	if err != nil {
		return nil, fmt.Errorf("failed to query witness receipts: %w", err)
	}
	defer rows.Close()

	var receipts []WitnessReceiptRecord
	for rows.Next() {
		var r WitnessReceiptRecord
		if err := rows.Scan(&r.EventSAID, &r.WitnessAID, &r.CesrSignature, &r.ReceivedAt); err != nil {
			return nil, err
		}
		receipts = append(receipts, r)
	}
	if receipts == nil {
		receipts = []WitnessReceiptRecord{}
	}
	return receipts, nil
}

// ── Guardianship ────────────────────────────────────────────────────────────

func (s *SQLiteStore) SaveGuardianship(record GuardianshipRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if record.CreatedAt == "" {
		record.CreatedAt = now
	}
	record.UpdatedAt = now

	emancipationJSON := "{}"
	if record.EmancipationTrigger != nil {
		b, err := json.Marshal(record.EmancipationTrigger)
		if err != nil {
			return fmt.Errorf("failed to marshal emancipation trigger: %w", err)
		}
		emancipationJSON = string(b)
	}

	coGuardiansJSON := "[]"
	if record.CoGuardians != nil {
		b, err := json.Marshal(record.CoGuardians)
		if err != nil {
			return fmt.Errorf("failed to marshal co-guardians: %w", err)
		}
		coGuardiansJSON = string(b)
	}

	metadataJSON := "{}"
	if record.Metadata != nil {
		b, err := json.Marshal(record.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metadataJSON = string(b)
	}

	_, err := s.db.Exec(`
		INSERT INTO guardianships (id, type, guardian_aid, dependent_aid, dependent_name, delegated_aid_prefix,
			status, hosting_type, hosting_url, created_at, updated_at, emancipation_json, co_guardians_json,
			multisig_threshold, metadata_json, credential_said)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			type                 = excluded.type,
			guardian_aid         = excluded.guardian_aid,
			dependent_aid        = excluded.dependent_aid,
			dependent_name       = excluded.dependent_name,
			delegated_aid_prefix = excluded.delegated_aid_prefix,
			status               = excluded.status,
			hosting_type         = excluded.hosting_type,
			hosting_url          = excluded.hosting_url,
			updated_at           = excluded.updated_at,
			emancipation_json    = excluded.emancipation_json,
			co_guardians_json    = excluded.co_guardians_json,
			multisig_threshold   = excluded.multisig_threshold,
			metadata_json        = excluded.metadata_json,
			credential_said      = excluded.credential_said`,
		record.ID, record.Type, record.GuardianAID, record.DependentAID,
		record.DependentName, record.DelegatedAIDPrefix, record.Status,
		record.HostingType, record.HostingURL, record.CreatedAt, record.UpdatedAt,
		emancipationJSON, coGuardiansJSON, record.MultisigThreshold, metadataJSON, record.CredentialSAID,
	)
	if err != nil {
		return fmt.Errorf("failed to save guardianship: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetGuardianships() ([]GuardianshipRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, type, guardian_aid, dependent_aid, dependent_name, delegated_aid_prefix,
			status, hosting_type, hosting_url, created_at, updated_at, emancipation_json,
			co_guardians_json, multisig_threshold, metadata_json, COALESCE(credential_said,'')
		 FROM guardianships ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query guardianships: %w", err)
	}
	defer rows.Close()
	return s.scanGuardianships(rows)
}

func (s *SQLiteStore) GetGuardianship(id string) (*GuardianshipRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, type, guardian_aid, dependent_aid, dependent_name, delegated_aid_prefix,
			status, hosting_type, hosting_url, created_at, updated_at, emancipation_json,
			co_guardians_json, multisig_threshold, metadata_json, COALESCE(credential_said,'')
		 FROM guardianships WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("failed to query guardianship: %w", err)
	}
	defer rows.Close()

	records, err := s.scanGuardianships(rows)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	return &records[0], nil
}

func (s *SQLiteStore) GetGuardianshipByDependentAID(dependentAID string) (*GuardianshipRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, type, guardian_aid, dependent_aid, dependent_name, delegated_aid_prefix,
			status, hosting_type, hosting_url, created_at, updated_at, emancipation_json,
			co_guardians_json, multisig_threshold, metadata_json, COALESCE(credential_said,'')
		 FROM guardianships WHERE dependent_aid = ? AND status = 'active' LIMIT 1`, dependentAID)
	if err != nil {
		return nil, fmt.Errorf("failed to query guardianship by dependent: %w", err)
	}
	defer rows.Close()
	records, err := s.scanGuardianships(rows)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	return &records[0], nil
}

func (s *SQLiteStore) DeleteGuardianship(id string) error {
	_, err := s.db.Exec(`DELETE FROM guardianships WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete guardianship: %w", err)
	}
	return nil
}

func (s *SQLiteStore) scanGuardianships(rows *sql.Rows) ([]GuardianshipRecord, error) {
	var records []GuardianshipRecord
	for rows.Next() {
		var r GuardianshipRecord
		var emancipationJSON, coGuardiansJSON, metadataJSON string
		if err := rows.Scan(&r.ID, &r.Type, &r.GuardianAID, &r.DependentAID,
			&r.DependentName, &r.DelegatedAIDPrefix, &r.Status, &r.HostingType,
			&r.HostingURL, &r.CreatedAt, &r.UpdatedAt, &emancipationJSON,
			&coGuardiansJSON, &r.MultisigThreshold, &metadataJSON, &r.CredentialSAID); err != nil {
			return nil, fmt.Errorf("failed to scan guardianship: %w", err)
		}
		if emancipationJSON != "" && emancipationJSON != "{}" {
			var trigger EmancipationTrigger
			if err := json.Unmarshal([]byte(emancipationJSON), &trigger); err == nil {
				r.EmancipationTrigger = &trigger
			}
		}
		if coGuardiansJSON != "" && coGuardiansJSON != "[]" {
			_ = json.Unmarshal([]byte(coGuardiansJSON), &r.CoGuardians)
		}
		if r.CoGuardians == nil {
			r.CoGuardians = []string{}
		}
		if metadataJSON != "" && metadataJSON != "{}" {
			_ = json.Unmarshal([]byte(metadataJSON), &r.Metadata)
		}
		if r.Metadata == nil {
			r.Metadata = map[string]string{}
		}
		records = append(records, r)
	}
	if records == nil {
		records = []GuardianshipRecord{}
	}
	return records, nil
}

// ── Service Providers ────────────────────────────────────────────────────────

func (s *SQLiteStore) SaveServiceProvider(record ServiceProviderRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if record.CreatedAt == "" {
		record.CreatedAt = now
	}
	record.UpdatedAt = now

	capabilitiesJSON := "[]"
	if record.Capabilities != nil {
		b, _ := json.Marshal(record.Capabilities)
		capabilitiesJSON = string(b)
	}

	configJSON := "{}"
	if record.Configuration != nil {
		b, _ := json.Marshal(record.Configuration)
		configJSON = string(b)
	}

	isDefault := 0
	if record.IsDefault {
		isDefault = 1
	}

	_, err := s.db.Exec(`
		INSERT INTO service_providers (id, provider_name, provider_aid, category, display_name, endpoint_url,
			status, health, health_checked_at, company_hq, server_region, identity_level, grape_score,
			capabilities_json, terms_url, terms_accepted_at, terms_version, connected_at,
			configuration_json, is_default, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			provider_name     = excluded.provider_name,
			provider_aid      = excluded.provider_aid,
			category          = excluded.category,
			display_name      = excluded.display_name,
			endpoint_url      = excluded.endpoint_url,
			status            = excluded.status,
			health            = excluded.health,
			health_checked_at = excluded.health_checked_at,
			company_hq        = excluded.company_hq,
			server_region     = excluded.server_region,
			identity_level    = excluded.identity_level,
			grape_score       = excluded.grape_score,
			capabilities_json = excluded.capabilities_json,
			terms_url         = excluded.terms_url,
			terms_accepted_at = excluded.terms_accepted_at,
			terms_version     = excluded.terms_version,
			connected_at      = excluded.connected_at,
			configuration_json= excluded.configuration_json,
			is_default        = excluded.is_default,
			source            = excluded.source,
			updated_at        = excluded.updated_at`,
		record.ID, record.ProviderName, record.ProviderAID, record.Category,
		record.DisplayName, record.EndpointURL, record.Status, record.Health,
		record.HealthCheckedAt, record.CompanyHQ, record.ServerRegion,
		record.IdentityLevel, record.GrapeScore, capabilitiesJSON, record.TermsURL,
		record.TermsAcceptedAt, record.TermsVersion, record.ConnectedAt,
		configJSON, isDefault, record.Source, record.CreatedAt, record.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save service provider: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetServiceProviders() ([]ServiceProviderRecord, error) {
	rows, err := s.db.Query(`SELECT id, provider_name, provider_aid, category, display_name, endpoint_url,
		status, health, health_checked_at, company_hq, server_region, identity_level, grape_score,
		capabilities_json, terms_url, terms_accepted_at, terms_version, connected_at,
		configuration_json, is_default, source, created_at, updated_at
		FROM service_providers ORDER BY category ASC, display_name ASC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query service providers: %w", err)
	}
	defer rows.Close()
	return s.scanServiceProviders(rows)
}

func (s *SQLiteStore) GetServiceProvider(id string) (*ServiceProviderRecord, error) {
	rows, err := s.db.Query(`SELECT id, provider_name, provider_aid, category, display_name, endpoint_url,
		status, health, health_checked_at, company_hq, server_region, identity_level, grape_score,
		capabilities_json, terms_url, terms_accepted_at, terms_version, connected_at,
		configuration_json, is_default, source, created_at, updated_at
		FROM service_providers WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("failed to query service provider: %w", err)
	}
	defer rows.Close()
	records, err := s.scanServiceProviders(rows)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	return &records[0], nil
}

func (s *SQLiteStore) GetServiceProvidersByCategory(category string) ([]ServiceProviderRecord, error) {
	rows, err := s.db.Query(`SELECT id, provider_name, provider_aid, category, display_name, endpoint_url,
		status, health, health_checked_at, company_hq, server_region, identity_level, grape_score,
		capabilities_json, terms_url, terms_accepted_at, terms_version, connected_at,
		configuration_json, is_default, source, created_at, updated_at
		FROM service_providers WHERE category = ? ORDER BY display_name ASC`, category)
	if err != nil {
		return nil, fmt.Errorf("failed to query service providers by category: %w", err)
	}
	defer rows.Close()
	return s.scanServiceProviders(rows)
}

func (s *SQLiteStore) GetServiceProvidersByStatus(status string) ([]ServiceProviderRecord, error) {
	rows, err := s.db.Query(`SELECT id, provider_name, provider_aid, category, display_name, endpoint_url,
		status, health, health_checked_at, company_hq, server_region, identity_level, grape_score,
		capabilities_json, terms_url, terms_accepted_at, terms_version, connected_at,
		configuration_json, is_default, source, created_at, updated_at
		FROM service_providers WHERE status = ? ORDER BY category ASC, display_name ASC`, status)
	if err != nil {
		return nil, fmt.Errorf("failed to query service providers by status: %w", err)
	}
	defer rows.Close()
	return s.scanServiceProviders(rows)
}

func (s *SQLiteStore) DeleteServiceProvider(id string) error {
	_, err := s.db.Exec(`DELETE FROM service_providers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete service provider: %w", err)
	}
	return nil
}

func (s *SQLiteStore) scanServiceProviders(rows *sql.Rows) ([]ServiceProviderRecord, error) {
	var records []ServiceProviderRecord
	for rows.Next() {
		var r ServiceProviderRecord
		var capabilitiesJSON, configJSON string
		var isDefault int
		if err := rows.Scan(&r.ID, &r.ProviderName, &r.ProviderAID, &r.Category,
			&r.DisplayName, &r.EndpointURL, &r.Status, &r.Health, &r.HealthCheckedAt,
			&r.CompanyHQ, &r.ServerRegion, &r.IdentityLevel, &r.GrapeScore,
			&capabilitiesJSON, &r.TermsURL, &r.TermsAcceptedAt, &r.TermsVersion,
			&r.ConnectedAt, &configJSON, &isDefault, &r.Source,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan service provider: %w", err)
		}
		r.IsDefault = isDefault == 1
		if capabilitiesJSON != "" && capabilitiesJSON != "[]" {
			_ = json.Unmarshal([]byte(capabilitiesJSON), &r.Capabilities)
		}
		if r.Capabilities == nil {
			r.Capabilities = []string{}
		}
		if configJSON != "" && configJSON != "{}" {
			_ = json.Unmarshal([]byte(configJSON), &r.Configuration)
		}
		if r.Configuration == nil {
			r.Configuration = map[string]string{}
		}
		records = append(records, r)
	}
	if records == nil {
		records = []ServiceProviderRecord{}
	}
	return records, nil
}

// AllocateNextRelationshipIndex atomically allocates and returns the next never-reused index
// for the namespace from the persisted high-water mark counter table. Separate namespaces
// ("contacts", "login") ensure independent sequences.
func (s *SQLiteStore) AllocateNextRelationshipIndex(namespace string) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	var nextIdx int
	err = tx.QueryRow(`SELECT next_index FROM relationship_counters WHERE namespace = ?`, namespace).Scan(&nextIdx)
	if err == sql.ErrNoRows {
		nextIdx = 1
		if namespace == "login" {
			nextIdx = 1000001
		}
		_, err = tx.Exec(`INSERT INTO relationship_counters (namespace, next_index) VALUES (?, ?)`, namespace, nextIdx+1)
		if err != nil {
			return 0, err
		}
		if err = tx.Commit(); err != nil {
			return 0, err
		}
		committed = true
		return nextIdx, nil
	} else if err != nil {
		return 0, err
	}

	// allocate current, bump
	_, err = tx.Exec(`UPDATE relationship_counters SET next_index = next_index + 1 WHERE namespace = ?`, namespace)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	committed = true
	return nextIdx, nil
}

// ── Reset ─────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) ResetAll() error {
	tables := []string{"kel", "identity", "contacts", "pending_requests", "profile", "settings", "endpoint", "contact_kels", "credentials", "credential_schemas", "presentations", "witness_receipts", "tasks", "guardianships", "service_providers"}
	for _, t := range tables {
		if _, err := s.db.Exec(`DELETE FROM ` + t); err != nil {
			return fmt.Errorf("failed to clear table %s: %w", t, err)
		}
	}
	log.Printf("[store] Reset all identity domain data")
	return nil
}

