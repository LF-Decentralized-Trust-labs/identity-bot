package watcher

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SQLiteStore implements Store against identity.db watcher tables.
type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

func (s *SQLiteStore) RecordFirstSeen(rec FirstSeenRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO kel_first_seen (
			aid, sequence_num, kel_digest, first_seen_at, last_confirmed_at,
			seen_count, source_type, source_url
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(aid, sequence_num) DO UPDATE SET
			kel_digest = excluded.kel_digest,
			last_confirmed_at = excluded.last_confirmed_at,
			seen_count = kel_first_seen.seen_count + 1`,
		rec.AID, rec.SequenceNum, rec.KelDigest,
		rec.FirstSeenAt.UTC().Format(time.RFC3339),
		rec.LastConfirmedAt.UTC().Format(time.RFC3339),
		rec.SeenCount, string(rec.SourceType), rec.SourceURL,
	)
	return err
}

func (s *SQLiteStore) getFirstSeen(aid string, seq int) (*FirstSeenRecord, error) {
	row := s.db.QueryRow(`
		SELECT aid, sequence_num, kel_digest, first_seen_at, last_confirmed_at,
		       seen_count, source_type, source_url
		FROM kel_first_seen WHERE aid = ? AND sequence_num = ?`, aid, seq)
	return scanFirstSeen(row)
}

func (s *SQLiteStore) listFirstSeen(aid string) ([]FirstSeenRecord, error) {
	rows, err := s.db.Query(`
		SELECT aid, sequence_num, kel_digest, first_seen_at, last_confirmed_at,
		       seen_count, source_type, source_url
		FROM kel_first_seen WHERE aid = ? ORDER BY sequence_num`, aid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FirstSeenRecord
	for rows.Next() {
		rec, err := scanFirstSeenRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) InsertDuplicityAlert(alert DuplicityAlert) (int64, error) {
	detectedAt := alert.DetectedAt.UTC().Format(time.RFC3339)
	if alert.Kind == "" {
		alert.Kind = AlertKindDuplicity
	}
	// An alert is identified by what it says and when (migration 46), so the
	// same one seen again within the same second is the same alert.
	res, err := s.db.Exec(`
		INSERT OR IGNORE INTO duplicity_alerts (
			aid, sequence_num, our_digest, their_digest, source_url, detected_at, resolved, resolution_note, kind, evidence_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		alert.AID, alert.SequenceNum, alert.OurDigest, alert.TheirDigest,
		alert.SourceURL, detectedAt,
		boolToInt(alert.Resolved), alert.ResolutionNote, alert.Kind, alert.Evidence,
	)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return res.LastInsertId()
	}
	var id int64
	err = s.db.QueryRow(`
		SELECT id FROM duplicity_alerts
		 WHERE aid = ? AND sequence_num = ? AND our_digest = ? AND their_digest = ? AND detected_at = ?`,
		alert.AID, alert.SequenceNum, alert.OurDigest, alert.TheirDigest, detectedAt).Scan(&id)
	return id, err
}

func (s *SQLiteStore) listDuplicityAlerts(aid string) ([]DuplicityAlert, error) {
	rows, err := s.db.Query(`
		`+alertColumns+`
		FROM duplicity_alerts WHERE aid = ? ORDER BY detected_at DESC, id DESC`, aid)
	if err != nil {
		return nil, err
	}
	return scanAlerts(rows)
}

const alertColumns = `SELECT id, aid, sequence_num, our_digest, their_digest, COALESCE(source_url, ''),
		       detected_at, COALESCE(resolved, 0), COALESCE(resolution_note, ''), COALESCE(kind, 'duplicity'), COALESCE(evidence_json, ''),
		       COALESCE((SELECT acknowledged_at FROM watcher_alert_ack WHERE alert_id = duplicity_alerts.id), '')`

func (s *SQLiteStore) listAllAlerts() ([]DuplicityAlert, error) {
	rows, err := s.db.Query(alertColumns + ` FROM duplicity_alerts ORDER BY detected_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	return scanAlerts(rows)
}

func (s *SQLiteStore) getAlert(id int64) (*DuplicityAlert, error) {
	rows, err := s.db.Query(alertColumns+` FROM duplicity_alerts WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	found, err := scanAlerts(rows)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return &found[0], nil
}

func scanAlerts(rows *sql.Rows) ([]DuplicityAlert, error) {
	defer rows.Close()
	var out []DuplicityAlert
	for rows.Next() {
		var a DuplicityAlert
		var detected, acked string
		var resolved int
		if err := rows.Scan(&a.ID, &a.AID, &a.SequenceNum, &a.OurDigest, &a.TheirDigest,
			&a.SourceURL, &detected, &resolved, &a.ResolutionNote, &a.Kind, &a.Evidence, &acked); err != nil {
			return nil, err
		}
		a.DetectedAt, _ = time.Parse(time.RFC3339, detected)
		a.AcknowledgedAt, _ = time.Parse(time.RFC3339, acked)
		a.Resolved = resolved != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// AcknowledgeAlert records that the owner has seen an alert. The first time
// stands: acknowledging again does not move it.
func (s *SQLiteStore) AcknowledgeAlert(id int64, at time.Time) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO watcher_alert_ack (alert_id, acknowledged_at) VALUES (?, ?)`,
		id, at.UTC().Format(time.RFC3339))
	return err
}

// ResolveAlert closes an alert with the owner's note. It also counts as seen.
// It returns ErrAlertAlreadyResolved when no open alert has that id.
func (s *SQLiteStore) ResolveAlert(id int64, note string, at time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// One statement decides: of two resolves at once, only one changes a row.
	res, err := tx.Exec(`UPDATE duplicity_alerts SET resolved = 1, resolution_note = ?
		 WHERE id = ? AND COALESCE(resolved, 0) = 0`, note, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAlertAlreadyResolved
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO watcher_alert_ack (alert_id, acknowledged_at) VALUES (?, ?)`,
		id, at.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) SaveContactCheck(c ContactCheck) error {
	if c.Sources == nil {
		c.Sources = []CheckSource{}
	}
	src, err := json.Marshal(c.Sources)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO watcher_contact_check (aid, checked_at, verdict, reason, sources_json)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(aid) DO UPDATE SET checked_at = excluded.checked_at, verdict = excluded.verdict,
		    reason = excluded.reason, sources_json = excluded.sources_json`,
		c.AID, c.CheckedAt, c.Verdict, c.Reason, string(src))
	return err
}

func (s *SQLiteStore) getContactCheck(aid string) (*ContactCheck, error) {
	rows, err := s.db.Query(`SELECT aid, checked_at, verdict, reason, sources_json FROM watcher_contact_check WHERE aid = ?`, aid)
	if err != nil {
		return nil, err
	}
	found, err := scanChecks(rows)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return &found[0], nil
}

func (s *SQLiteStore) listContactChecks() ([]ContactCheck, error) {
	rows, err := s.db.Query(`SELECT aid, checked_at, verdict, reason, sources_json FROM watcher_contact_check ORDER BY aid`)
	if err != nil {
		return nil, err
	}
	return scanChecks(rows)
}

func scanChecks(rows *sql.Rows) ([]ContactCheck, error) {
	defer rows.Close()
	var out []ContactCheck
	for rows.Next() {
		var c ContactCheck
		var src string
		if err := rows.Scan(&c.AID, &c.CheckedAt, &c.Verdict, &c.Reason, &src); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(src), &c.Sources); err != nil || c.Sources == nil {
			c.Sources = []CheckSource{}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) IsOptedOut(aid string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM watcher_opt_out WHERE aid = ?`, aid).Scan(&n)
	return n > 0, err
}

func (s *SQLiteStore) SetOptOut(aid string, optedOut bool) error {
	if optedOut {
		_, err := s.db.Exec(`INSERT OR IGNORE INTO watcher_opt_out (aid) VALUES (?)`, aid)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM watcher_opt_out WHERE aid = ?`, aid)
	return err
}

func (s *SQLiteStore) GetConfig(key string) (string, error) {
	var val string
	err := s.db.QueryRow(`SELECT value FROM watcher_config WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

func (s *SQLiteStore) SetConfig(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO watcher_config (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *SQLiteStore) PruneIntermediate(aid string, keepSeqs []int) error {
	if len(keepSeqs) == 0 {
		return nil
	}
	placeholders := strings.Repeat("?,", len(keepSeqs))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]interface{}, 0, len(keepSeqs)+1)
	args = append(args, aid)
	for _, seq := range keepSeqs {
		args = append(args, seq)
	}
	_, err := s.db.Exec(
		fmt.Sprintf(`DELETE FROM kel_first_seen WHERE aid = ? AND sequence_num NOT IN (%s)`, placeholders),
		args...,
	)
	return err
}

func (s *SQLiteStore) PruneStale(before time.Time) (int, error) {
	res, err := s.db.Exec(`
		DELETE FROM kel_first_seen
		WHERE aid IN (
			SELECT aid FROM kel_first_seen
			GROUP BY aid
			HAVING MAX(last_confirmed_at) < ?
		)`, before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func scanFirstSeen(row *sql.Row) (*FirstSeenRecord, error) {
	var rec FirstSeenRecord
	var firstSeen, lastConfirmed, sourceType string
	if err := row.Scan(&rec.AID, &rec.SequenceNum, &rec.KelDigest,
		&firstSeen, &lastConfirmed, &rec.SeenCount, &sourceType, &rec.SourceURL); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	rec.FirstSeenAt, _ = time.Parse(time.RFC3339, firstSeen)
	rec.LastConfirmedAt, _ = time.Parse(time.RFC3339, lastConfirmed)
	rec.SourceType = SourceType(sourceType)
	return &rec, nil
}

func scanFirstSeenRow(rows *sql.Rows) (*FirstSeenRecord, error) {
	var rec FirstSeenRecord
	var firstSeen, lastConfirmed, sourceType string
	if err := rows.Scan(&rec.AID, &rec.SequenceNum, &rec.KelDigest,
		&firstSeen, &lastConfirmed, &rec.SeenCount, &sourceType, &rec.SourceURL); err != nil {
		return nil, err
	}
	rec.FirstSeenAt, _ = time.Parse(time.RFC3339, firstSeen)
	rec.LastConfirmedAt, _ = time.Parse(time.RFC3339, lastConfirmed)
	rec.SourceType = SourceType(sourceType)
	return &rec, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
