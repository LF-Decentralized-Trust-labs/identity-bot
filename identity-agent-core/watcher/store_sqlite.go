package watcher

import (
	"database/sql"
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

func (s *SQLiteStore) GetFirstSeen(aid string, seq int) (*FirstSeenRecord, error) {
	row := s.db.QueryRow(`
		SELECT aid, sequence_num, kel_digest, first_seen_at, last_confirmed_at,
		       seen_count, source_type, source_url
		FROM kel_first_seen WHERE aid = ? AND sequence_num = ?`, aid, seq)
	return scanFirstSeen(row)
}

func (s *SQLiteStore) ListFirstSeen(aid string) ([]FirstSeenRecord, error) {
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
	res, err := s.db.Exec(`
		INSERT INTO duplicity_alerts (
			aid, sequence_num, our_digest, their_digest, source_url, detected_at, resolved, resolution_note
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		alert.AID, alert.SequenceNum, alert.OurDigest, alert.TheirDigest,
		alert.SourceURL, alert.DetectedAt.UTC().Format(time.RFC3339),
		boolToInt(alert.Resolved), alert.ResolutionNote,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLiteStore) ListDuplicityAlerts(aid string) ([]DuplicityAlert, error) {
	rows, err := s.db.Query(`
		SELECT id, aid, sequence_num, our_digest, their_digest, source_url,
		       detected_at, resolved, resolution_note
		FROM duplicity_alerts WHERE aid = ? ORDER BY detected_at DESC`, aid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DuplicityAlert
	for rows.Next() {
		var a DuplicityAlert
		var detected string
		var resolved int
		if err := rows.Scan(&a.ID, &a.AID, &a.SequenceNum, &a.OurDigest, &a.TheirDigest,
			&a.SourceURL, &detected, &resolved, &a.ResolutionNote); err != nil {
			return nil, err
		}
		a.DetectedAt, _ = time.Parse(time.RFC3339, detected)
		a.Resolved = resolved != 0
		out = append(out, a)
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
