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

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO contacts (aid, alias, public_key, oobi_url, verified, discovered_at, status, role, jcard_json, photo, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(aid) DO UPDATE SET
			alias = excluded.alias,
			public_key = excluded.public_key,
			oobi_url = excluded.oobi_url,
			verified = excluded.verified,
			status = excluded.status,
			role = excluded.role,
			jcard_json = excluded.jcard_json,
			photo = excluded.photo,
			updated_at = excluded.updated_at`,
		contact.AID, contact.Alias, contact.PublicKey, contact.OobiURL,
		contact.Verified, contact.DiscoveredAt, contact.Status, contact.Role,
		jcardJSON, contact.Photo, now,
	)
	if err != nil {
		return fmt.Errorf("failed to save contact: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetContacts() ([]ContactRecord, error) {
	rows, err := s.db.Query(
		`SELECT aid, alias, public_key, oobi_url, verified, discovered_at, status, role, jcard_json, photo
		 FROM contacts ORDER BY alias ASC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query contacts: %w", err)
	}
	defer rows.Close()
	return s.scanContacts(rows)
}

func (s *SQLiteStore) GetContact(aid string) (*ContactRecord, error) {
	rows, err := s.db.Query(
		`SELECT aid, alias, public_key, oobi_url, verified, discovered_at, status, role, jcard_json, photo
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
		`SELECT aid, alias, public_key, oobi_url, verified, discovered_at, status, role, jcard_json, photo
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
			&c.Verified, &c.DiscoveredAt, &c.Status, &c.Role, &jcardJSON, &c.Photo); err != nil {
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

func (s *SQLiteStore) SaveSettings(settings SettingsData) error {
	_, err := s.db.Exec(`
		INSERT INTO settings (tunnel_provider, ngrok_auth_token, cloudflare_tunnel_token, tunnel_domain, tunnel_extension)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(rowid) DO UPDATE SET
			tunnel_provider = excluded.tunnel_provider,
			ngrok_auth_token = excluded.ngrok_auth_token,
			cloudflare_tunnel_token = excluded.cloudflare_tunnel_token,
			tunnel_domain = excluded.tunnel_domain,
			tunnel_extension = excluded.tunnel_extension`,
		settings.TunnelProvider, settings.NgrokAuthToken,
		settings.CloudflareTunnelToken, settings.TunnelDomain, settings.TunnelExtension,
	)
	if err != nil {
		return fmt.Errorf("failed to save settings: %w", err)
	}
	return nil
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

func (s *SQLiteStore) SaveCredential(record CredentialRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO credentials (said, issuer_aid, holder_aid, schema_said, acdc_json, ixn_said, cesr_signature, issued_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(said) DO UPDATE SET
			cesr_signature = excluded.cesr_signature,
			status         = excluded.status`,
		record.SAID, record.IssuerAID, record.HolderAID, record.SchemaSAID,
		record.AcdcJson, record.IxnSAID, record.CesrSignature, record.IssuedAt, record.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetCredential(said string) (*CredentialRecord, error) {
	var r CredentialRecord
	err := s.db.QueryRow(
		`SELECT said, issuer_aid, holder_aid, schema_said, acdc_json, ixn_said, cesr_signature, issued_at, status
		 FROM credentials WHERE said = ?`, said,
	).Scan(&r.SAID, &r.IssuerAID, &r.HolderAID, &r.SchemaSAID,
		&r.AcdcJson, &r.IxnSAID, &r.CesrSignature, &r.IssuedAt, &r.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return &r, nil
}

func (s *SQLiteStore) GetCredentials() ([]CredentialRecord, error) {
	rows, err := s.db.Query(
		`SELECT said, issuer_aid, holder_aid, schema_said, acdc_json, ixn_said, cesr_signature, issued_at, status
		 FROM credentials ORDER BY issued_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}
	defer rows.Close()

	var creds []CredentialRecord
	for rows.Next() {
		var r CredentialRecord
		if err := rows.Scan(&r.SAID, &r.IssuerAID, &r.HolderAID, &r.SchemaSAID,
			&r.AcdcJson, &r.IxnSAID, &r.CesrSignature, &r.IssuedAt, &r.Status); err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}
		creds = append(creds, r)
	}
	if creds == nil {
		creds = []CredentialRecord{}
	}
	return creds, nil
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

// ── Reset ─────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) ResetAll() error {
	tables := []string{"kel", "identity", "contacts", "pending_requests", "profile", "settings", "endpoint", "contact_kels", "credentials", "presentations"}
	for _, t := range tables {
		if _, err := s.db.Exec(`DELETE FROM ` + t); err != nil {
			return fmt.Errorf("failed to clear table %s: %w", t, err)
		}
	}
	log.Printf("[store] Reset all identity domain data")
	return nil
}

