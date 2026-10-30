package activitylog

import (
	"database/sql"
	"errors"
)

// A stretch of the log can be handed to somebody who checks it elsewhere.
//
// An exported conversation carries the rows of the log written while it ran,
// exactly as they are kept, so a verifier with no access to this database can
// check each row's signature and the links between them. The verifier applies
// the same reading and the same signature check this log applies to itself
// (VerifyChain), so a row means one thing wherever it is checked.

// StoredRow is one row of the log exactly as kept: its id, its record, and the
// bytes its signature covers.
type StoredRow struct {
	ID            int64  `json:"id"`
	Record        string `json:"record"`
	SignedPayload string `json:"signed_payload,omitempty"`
}

// FirstRowFor is the oldest row filed under a piece of work, and whether there
// is one.
func (l *Log) FirstRowFor(workItem string) (int64, bool, error) {
	var id sql.NullInt64
	if err := l.db.QueryRow(`SELECT MIN(id) FROM invocation_log WHERE work_item = ?`, workItem).Scan(&id); err != nil {
		return 0, false, err
	}
	return id.Int64, id.Valid, nil
}

// StoredRows returns the rows from id from through id to, oldest first, as
// kept. A row whose record is missing comes back with an empty record, so the
// gap is seen by whoever checks it rather than closed up here.
func (l *Log) StoredRows(from, to int64) ([]StoredRow, error) {
	if to < from {
		return nil, errors.New("the stretch of the log asked for ends before it begins")
	}
	rows, err := l.db.Query(`SELECT id, COALESCE(event_json, ''), COALESCE(signed_payload, '')
		FROM invocation_log WHERE id >= ? AND id <= ? ORDER BY id ASC`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredRow{}
	for rows.Next() {
		var r StoredRow
		if err := rows.Scan(&r.ID, &r.Record, &r.SignedPayload); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CheckStoredRow reads one row as kept and checks it: that the record is one
// this log writes, that its signature by the key keys gives for its signer
// verifies over the bytes kept beside it, and that those bytes say what the
// record says. It returns the event and why the row fails, or "" when it
// holds. Every row written since signed bytes were kept carries them, so a row
// without them fails here rather than being checked a weaker way.
func CheckStoredRow(row StoredRow, keys EventKeys) (InvocationEvent, string, error) {
	if row.Record == "" {
		return InvocationEvent{}, "the record is missing", nil
	}
	ev, err := decodeEvent([]byte(row.Record))
	if err != nil {
		return ev, "the record cannot be read: " + err.Error(), nil
	}
	why, err := verifyEventSignature(ev, []byte(row.SignedPayload), true, keys)
	return ev, why, err
}
