package witness

import (
	"database/sql"
	"fmt"
	"time"

	"identity-agent-core/store"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

func (s *SQLiteStore) GetConfig(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM witness_config WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *SQLiteStore) SetConfig(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO witness_config (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *SQLiteStore) GetContactMeta(aid string) (*ContactMeta, error) {
	row := s.db.QueryRow(`
		SELECT contact_aid, backend_type, witness_status, offline_count, is_mutual, is_commercial,
		       COALESCE(witnessing_for, 0), enrolled_at, last_receipt_at, last_health_check,
		       COALESCE(witness_key, ''), COALESCE(entity_type, '')
		FROM witness_contact_meta WHERE contact_aid = ?`, aid)
	var m ContactMeta
	var mutual, commercial, witnessingFor int
	err := row.Scan(&m.ContactAID, &m.BackendType, &m.WitnessStatus, &m.OfflineCount,
		&mutual, &commercial, &witnessingFor, &m.EnrolledAt, &m.LastReceiptAt, &m.LastHealthCheck,
		&m.WitnessKey, &m.EntityType)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.IsMutual = mutual != 0
	m.IsCommercial = commercial != 0
	m.WitnessingFor = witnessingFor != 0
	return &m, nil
}

func (s *SQLiteStore) SaveContactMeta(m ContactMeta) error {
	mutual, commercial, witnessingFor := 0, 0, 0
	if m.IsMutual {
		mutual = 1
	}
	if m.IsCommercial {
		commercial = 1
	}
	if m.WitnessingFor {
		witnessingFor = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO witness_contact_meta (
			contact_aid, backend_type, witness_status, offline_count, is_mutual, is_commercial,
			witnessing_for, enrolled_at, last_receipt_at, last_health_check, witness_key, entity_type
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(contact_aid) DO UPDATE SET
			backend_type = excluded.backend_type,
			witness_key = excluded.witness_key,
			entity_type = excluded.entity_type,
			witness_status = excluded.witness_status,
			offline_count = excluded.offline_count,
			is_mutual = excluded.is_mutual,
			is_commercial = excluded.is_commercial,
			witnessing_for = excluded.witnessing_for,
			enrolled_at = excluded.enrolled_at,
			last_receipt_at = excluded.last_receipt_at,
			last_health_check = excluded.last_health_check`,
		m.ContactAID, m.BackendType, m.WitnessStatus, m.OfflineCount,
		mutual, commercial, witnessingFor, m.EnrolledAt, m.LastReceiptAt, m.LastHealthCheck,
		m.WitnessKey, m.EntityType,
	)
	return err
}

func (s *SQLiteStore) ListContactMeta() ([]ContactMeta, error) {
	rows, err := s.db.Query(`
		SELECT contact_aid, backend_type, witness_status, offline_count, is_mutual, is_commercial,
		       COALESCE(witnessing_for, 0), enrolled_at, last_receipt_at, last_health_check,
		       COALESCE(witness_key, ''), COALESCE(entity_type, '')
		FROM witness_contact_meta ORDER BY contact_aid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ContactMeta
	for rows.Next() {
		var m ContactMeta
		var mutual, commercial, witnessingFor int
		if err := rows.Scan(&m.ContactAID, &m.BackendType, &m.WitnessStatus, &m.OfflineCount,
			&mutual, &commercial, &witnessingFor, &m.EnrolledAt, &m.LastReceiptAt, &m.LastHealthCheck,
			&m.WitnessKey, &m.EntityType); err != nil {
			return nil, err
		}
		m.IsMutual = mutual != 0
		m.IsCommercial = commercial != 0
		m.WitnessingFor = witnessingFor != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) StoreKelEvent(ev KelEvent) error {
	return storeKelEvent(s.db, ev)
}

// execer is a database or a transaction.
type execer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

func storeKelEvent(db execer, ev KelEvent) error {
	res, err := db.Exec(`
		INSERT INTO witness_kel_events (signer_aid, sequence_num, event_json, event_said, stored_at, raw_bytes_b64, cesr_signature, signatures)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(signer_aid, sequence_num) DO NOTHING`,
		ev.SignerAID, ev.SequenceNum, ev.EventJSON, ev.EventSAID, ev.StoredAt,
		ev.RawBytesB64, firstOf(ev.Signatures, ev.CesrSignature), signatureList(ev.Signatures))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("an event of %s is already held at sequence number %d", ev.SignerAID, ev.SequenceNum)
	}
	return nil
}

func firstOf(sigs []string, otherwise string) string {
	if len(sigs) > 0 {
		return sigs[0]
	}
	return otherwise
}

func signatureList(sigs []string) string { return store.SignatureListColumn(sigs) }

func readSignatureList(stored string) ([]string, error) {
	sigs, err := store.ReadSignatureListColumn(stored)
	if err != nil {
		return nil, fmt.Errorf("a stored signature list is unreadable: %w", err)
	}
	return sigs, nil
}

func (s *SQLiteStore) GetKelEvents(signerAID string) ([]KelEvent, error) {
	rows, err := s.db.Query(`
		SELECT signer_aid, sequence_num, event_json, event_said, stored_at, raw_bytes_b64, cesr_signature, signatures
		FROM witness_kel_events WHERE signer_aid = ? ORDER BY sequence_num`, signerAID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KelEvent
	for rows.Next() {
		var ev KelEvent
		var sigs string
		if err := rows.Scan(&ev.SignerAID, &ev.SequenceNum, &ev.EventJSON, &ev.EventSAID, &ev.StoredAt,
			&ev.RawBytesB64, &ev.CesrSignature, &sigs); err != nil {
			return nil, err
		}
		if ev.Signatures, err = readSignatureList(sigs); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SetKelSignatures(signerAID string, seq int, signatures []string) error {
	_, err := s.db.Exec(`UPDATE witness_kel_events SET signatures = ?, cesr_signature = ?
		WHERE signer_aid = ? AND sequence_num = ?`,
		signatureList(signatures), firstOf(signatures, ""), signerAID, seq)
	return err
}

func (s *SQLiteStore) SupersedeKelEvents(signerAID string, by KelEvent, tip int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var last sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(sequence_num) FROM witness_kel_events WHERE signer_aid = ?`,
		signerAID).Scan(&last); err != nil {
		return err
	}
	if !last.Valid || int(last.Int64) != tip {
		return fmt.Errorf("the key log of %s moved while the recovery rotation was judged", signerAID)
	}
	if _, err := tx.Exec(`
		INSERT OR IGNORE INTO witness_kel_superseded (signer_aid, sequence_num, event_said, raw_bytes_b64, signatures, superseded_by, superseded_at)
		SELECT signer_aid, sequence_num, event_said, raw_bytes_b64,
		       CASE WHEN signatures != '' THEN signatures
		            WHEN cesr_signature != '' THEN json_array(cesr_signature) ELSE '' END,
		       ?, ?
		FROM witness_kel_events WHERE signer_aid = ? AND sequence_num >= ?`,
		by.EventSAID, by.StoredAt, signerAID, by.SequenceNum); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM witness_kel_events WHERE signer_aid = ? AND sequence_num >= ?`,
		signerAID, by.SequenceNum); err != nil {
		return err
	}
	if err := storeKelEvent(tx, by); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetSupersededKelEvents(signerAID string) ([]KelEvent, error) {
	rows, err := s.db.Query(`SELECT signer_aid, sequence_num, event_said, raw_bytes_b64, signatures, superseded_at
		FROM witness_kel_superseded WHERE signer_aid = ? ORDER BY rowid`, signerAID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KelEvent
	for rows.Next() {
		var ev KelEvent
		var sigs string
		if err := rows.Scan(&ev.SignerAID, &ev.SequenceNum, &ev.EventSAID, &ev.RawBytesB64,
			&sigs, &ev.StoredAt); err != nil {
			return nil, err
		}
		if ev.Signatures, err = readSignatureList(sigs); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SaveKelConflict(c KelConflict) error {
	_, err := s.db.Exec(`INSERT INTO witness_kel_conflicts
		(signer_aid, sequence_num, event_said, raw_bytes_b64, signatures, held_said, seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(signer_aid, event_said) DO NOTHING`,
		c.SignerAID, c.SequenceNum, c.EventSAID, c.RawBytesB64, signatureList(c.Signatures),
		c.HeldSAID, c.SeenAt)
	return err
}

func (s *SQLiteStore) GetKelConflicts(signerAID string) ([]KelConflict, error) {
	rows, err := s.db.Query(`SELECT signer_aid, sequence_num, event_said, raw_bytes_b64, signatures, held_said, seen_at
		FROM witness_kel_conflicts WHERE signer_aid = ? ORDER BY sequence_num, seen_at`, signerAID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KelConflict
	for rows.Next() {
		var c KelConflict
		var sigs string
		if err := rows.Scan(&c.SignerAID, &c.SequenceNum, &c.EventSAID, &c.RawBytesB64, &sigs,
			&c.HeldSAID, &c.SeenAt); err != nil {
			return nil, err
		}
		if c.Signatures, err = readSignatureList(sigs); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) LastKelSeq(signerAID string) (int, error) {
	var seq sql.NullInt64
	err := s.db.QueryRow(`SELECT MAX(sequence_num) FROM witness_kel_events WHERE signer_aid = ?`, signerAID).Scan(&seq)
	if err != nil {
		return -1, err
	}
	if !seq.Valid {
		return -1, nil
	}
	return int(seq.Int64), nil
}

func (s *SQLiteStore) CountKelEvents(signerAID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM witness_kel_events WHERE signer_aid = ?`, signerAID).Scan(&n)
	return n, err
}

func (s *SQLiteStore) SaveIssuedReceipt(r IssuedReceipt) error {
	_, err := s.db.Exec(`
		INSERT INTO witness_receipts_issued (
			signer_aid, event_said, sequence_num, witness_aid, receipt_json, cesr_signature, issued_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.SignerAID, r.EventSAID, r.SequenceNum, r.WitnessAID, r.ReceiptJSON, r.CesrSignature, r.IssuedAt)
	return err
}

func (s *SQLiteStore) GetIssuedReceipt(signerAID, eventSAID string) (*IssuedReceipt, error) {
	var r IssuedReceipt
	err := s.db.QueryRow(`
		SELECT signer_aid, event_said, sequence_num, witness_aid, receipt_json, cesr_signature, issued_at
		FROM witness_receipts_issued WHERE signer_aid = ? AND event_said = ?
		ORDER BY issued_at DESC LIMIT 1`, signerAID, eventSAID).Scan(
		&r.SignerAID, &r.EventSAID, &r.SequenceNum, &r.WitnessAID, &r.ReceiptJSON, &r.CesrSignature, &r.IssuedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *SQLiteStore) GetFinalization(eventSAID string) (*FinalizationState, error) {
	row := s.db.QueryRow(`
		SELECT event_said, signer_aid, sequence_num, state, receipt_count, threshold, started_at, updated_at
		FROM witness_finalization WHERE event_said = ?`, eventSAID)
	var f FinalizationState
	err := row.Scan(&f.EventSAID, &f.SignerAID, &f.SequenceNum, &f.State, &f.ReceiptCount,
		&f.Threshold, &f.StartedAt, &f.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *SQLiteStore) SaveFinalization(f FinalizationState) error {
	_, err := s.db.Exec(`
		INSERT INTO witness_finalization (
			event_said, signer_aid, sequence_num, state, receipt_count, threshold, started_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(event_said) DO UPDATE SET
			state = excluded.state,
			receipt_count = excluded.receipt_count,
			updated_at = excluded.updated_at`,
		f.EventSAID, f.SignerAID, f.SequenceNum, f.State, f.ReceiptCount,
		f.Threshold, f.StartedAt, f.UpdatedAt)
	return err
}

func (s *SQLiteStore) CountWitnessingFor() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM witness_contact_meta WHERE witnessing_for = 1`).Scan(&n)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		return n, nil
	}
	err = s.db.QueryRow(`SELECT COUNT(DISTINCT signer_aid) FROM witness_kel_events`).Scan(&n)
	return n, err
}

func (s *SQLiteStore) RecordSelfHealAttempt(contactAID string, at string) error {
	_, err := s.db.Exec(`INSERT INTO witness_self_heal_log (contact_aid, attempted_at) VALUES (?, ?)`, contactAID, at)
	return err
}

func (s *SQLiteStore) LastSelfHealAttempt(contactAID string) (string, error) {
	var at string
	err := s.db.QueryRow(`
		SELECT attempted_at FROM witness_self_heal_log WHERE contact_aid = ?
		ORDER BY id DESC LIMIT 1`, contactAID).Scan(&at)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return at, err
}

func (s *SQLiteStore) CountSelfHealAttemptsSince(since string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM witness_self_heal_log WHERE attempted_at >= ?`, since).Scan(&n)
	return n, err
}

func InitDefaultConfig(s Store, backendType string) error {
	defaults := map[string]string{
		"threshold":       fmt.Sprintf("%d", DefaultThreshold),
		"max_witnesses":   fmt.Sprintf("%d", MaxWitnessSetSize),
		"target_contacts": fmt.Sprintf("%d", TargetContactWitnesses),
		"backend_type":    backendType,
	}
	for k, v := range defaults {
		cur, _ := s.GetConfig(k)
		if cur == "" {
			if err := s.SetConfig(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func NowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
