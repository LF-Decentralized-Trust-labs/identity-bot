package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/ownership"
)

// An owner identity's key log is extended only at a place reserved first.
//
// An owner identity anchors, in its own key log, the establishment event of
// the Identity Agent it owns (ADR-087). Two different events signed at one
// place of that log are duplicity, and a verifier shown them treats nothing
// as owned by that identity. So the place, the event before it, the digest
// and the exact bytes are written down, durably, before a signature over them
// exists (ADR-061 section 4). A device that stops between the two finds the
// row when it starts again and signs those bytes, never others.
//
// The row's primary key is the rule: one reservation to a place, for good,
// in this database. That holds across crashes, restarts and callers racing
// each other. It does not hold across databases: a device restored from an
// older backup, or a second copy of the Identity Agent with the same root
// seed, has no row for a place the other already used. Keeping one event to a
// place across copies needs the owner identity's witnesses (ADR-087 decisions
// 10 and 12), which the writer of the log asks before it signs.

// The states of a reservation.
const (
	// OwnerLogReserved is a place whose event is not yet kept, signed or not.
	OwnerLogReserved = "reserved"
	// OwnerLogDone is a place whose signed event is in the kept log.
	OwnerLogDone = "done"
)

// OwnerLogReservation is one place in an owner identity's key log and the
// only event this database lets be signed there.
type OwnerLogReservation struct {
	OwnerAID string
	SN       int
	// PriorDigest is the digest of the event at SN-1.
	PriorDigest string
	// Digest is the digest of the event reserved.
	Digest string
	// RawB64 is the exact bytes of the event reserved, base64.
	RawB64 string
	State  string
}

// Why a reservation is refused. Each is final for the owner identity it
// names: nothing a caller sends again changes the answer.
var (
	ErrNotAnOwnerIdentity       = errors.New("this device did not mint that owner identity")
	ErrOwnerIdentityGivenUp     = errors.New("the owner identity was given up, so it anchors nothing")
	ErrOwnerIdentityDuplicitous = errors.New("two events are known at one place of the owner identity's key log, so it anchors nothing")
	ErrOwnerLogNamesAnother     = errors.New("the owner identity's key log already anchors another Identity Agent")
	ErrOwnerLogPlaceNotNext     = errors.New("the place does not follow the owner identity's kept key log")
)

// ReserveOwnerLogPlace reserves r's place for r's bytes and records m as the
// one Identity Agent the owner identity anchors, in one transaction that is on
// disk before this returns. It returns the reservation in force at that place:
// r itself, or the one already there, which is never replaced. A caller signs
// only what is returned. r's bytes must be the interaction r describes, and
// must anchor m (OwnerLogReservation.Anchors).
func (s *SQLiteStore) ReserveOwnerLogPlace(r OwnerLogReservation, m string) (OwnerLogReservation, error) {
	if m == "" {
		return OwnerLogReservation{}, fmt.Errorf("a reservation names the Identity Agent the event anchors")
	}
	sealed, err := r.Anchors()
	if err != nil {
		return OwnerLogReservation{}, err
	}
	if sealed != m {
		return OwnerLogReservation{}, fmt.Errorf("the reserved bytes anchor %s, not %s", sealed, m)
	}
	inForce := r
	inForce.State = OwnerLogReserved
	err = s.durably(func(tx *sql.Tx) error {
		id, found, err := machineOwnerIdentity(tx, r.OwnerAID)
		if err != nil {
			return err
		}
		switch {
		case !found:
			return ErrNotAnOwnerIdentity
		case id.GivenUpFor != "":
			return ErrOwnerIdentityGivenUp
		case id.DuplicitousAt != nil:
			return ErrOwnerIdentityDuplicitous
		case id.AnchoredM != "" && id.AnchoredM != m:
			return fmt.Errorf("%w: %s", ErrOwnerLogNamesAnother, id.AnchoredM)
		}
		held, err := ownerLogReservations(tx, r.OwnerAID)
		if err != nil {
			return err
		}
		for _, h := range held {
			if h.SN == r.SN {
				inForce = h
				return nil
			}
			if h.State != OwnerLogDone {
				return fmt.Errorf("%w: sequence number %d is reserved and its event is not yet kept",
					ErrOwnerLogPlaceNotNext, h.SN)
			}
			if h.SN > r.SN {
				return fmt.Errorf("%w: sequence number %d was reserved after it", ErrOwnerLogPlaceNotNext, h.SN)
			}
		}
		var tipSN int
		var tipRaw string
		switch err := tx.QueryRow(`SELECT seq_num, raw_bytes_b64 FROM kel WHERE aid = ? ORDER BY seq_num DESC LIMIT 1`,
			r.OwnerAID).Scan(&tipSN, &tipRaw); {
		case errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("%w: no key log is kept for %s", ErrOwnerLogPlaceNotNext, r.OwnerAID)
		case err != nil:
			return fmt.Errorf("could not read the owner identity's key log: %w", err)
		}
		if tip, _ := drivers.EventIDOfRawB64(tipRaw); tipSN != r.SN-1 || tip == "" || tip != r.PriorDigest {
			return fmt.Errorf("%w: its tip is sequence number %d (%s)", ErrOwnerLogPlaceNotNext, tipSN, tip)
		}
		if _, err := tx.Exec(`UPDATE machine_owner_identities SET anchored_m = ? WHERE aid = ?`, m, r.OwnerAID); err != nil {
			return fmt.Errorf("could not record which Identity Agent the owner identity anchors: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO owner_log_reservations
			(owner_aid, seq_num, prior_digest, digest, event_bytes_b64, state) VALUES (?, ?, ?, ?, ?, ?)`,
			r.OwnerAID, r.SN, r.PriorDigest, r.Digest, r.RawB64, OwnerLogReserved); err != nil {
			return fmt.Errorf("could not reserve the place: %w", err)
		}
		return nil
	})
	if err != nil {
		return OwnerLogReservation{}, err
	}
	return inForce, nil
}

// Anchors checks that a reservation's fields describe its own bytes, read as
// the bytes are written and never from the fields alone, and returns the
// Identity Agent whose event the reserved interaction anchors. The bytes must
// be one interaction event of the owner identity, at the place and after the
// event the reservation states, whose digest computed from the bytes is the
// digest it states, carrying exactly one event seal
// (ownership.TheAnchorIn). A reservation restored from a backup is a row
// nothing wrote here, so this is asked of every reservation before its bytes
// are signed, wherever it came from.
func (r OwnerLogReservation) Anchors() (string, error) {
	if r.OwnerAID == "" || r.SN < 1 || r.PriorDigest == "" || r.Digest == "" || r.RawB64 == "" {
		return "", fmt.Errorf("a reservation needs the owner identity, a place after the founding, " +
			"the digest before it, the digest reserved and the event's bytes")
	}
	raw, err := drivers.DecodeRawBytes(r.RawB64)
	if err != nil {
		return "", fmt.Errorf("the reserved bytes are not base64: %w", err)
	}
	notIt := fmt.Errorf("the reserved bytes are not the interaction of %s at sequence number %d "+
		"that the reservation describes", r.OwnerAID, r.SN)
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", notIt, err)
	}
	if ev.Ilk != "ixn" || ev.Identifier != r.OwnerAID || ev.SN != uint64(r.SN) || ev.PriorSAID != r.PriorDigest ||
		ev.SAID != r.Digest {
		return "", notIt
	}
	if computed, err := keri.ComputeSAID(raw); err != nil || computed != r.Digest {
		return "", fmt.Errorf("%w: its digest is not the digest of its bytes", notIt)
	}
	seal, err := ownership.TheAnchorIn(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", notIt, err)
	}
	return seal.Identifier, nil
}

// OwnerLogReservations are the places reserved in an owner identity's key
// log, in order.
func (s *SQLiteStore) OwnerLogReservations(ownerAID string) ([]OwnerLogReservation, error) {
	return ownerLogReservations(s.db, ownerAID)
}

func ownerLogReservations(q interface {
	Query(string, ...any) (*sql.Rows, error)
}, ownerAID string) ([]OwnerLogReservation, error) {
	rows, err := q.Query(`SELECT owner_aid, seq_num, prior_digest, digest, event_bytes_b64, state
		FROM owner_log_reservations WHERE owner_aid = ? ORDER BY seq_num`, ownerAID)
	if err != nil {
		return nil, fmt.Errorf("could not read the owner log's reservations: %w", err)
	}
	defer rows.Close()
	var out []OwnerLogReservation
	for rows.Next() {
		var r OwnerLogReservation
		if err := rows.Scan(&r.OwnerAID, &r.SN, &r.PriorDigest, &r.Digest, &r.RawB64, &r.State); err != nil {
			return nil, fmt.Errorf("could not read a reservation: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// KeepOwnerLogEvent adds a signed event to an owner identity's kept key log
// and marks its reservation done, together. It keeps only the bytes reserved
// at that place, signed, and never over a different event already kept there.
// Keeping the same event again changes nothing.
func (s *SQLiteStore) KeepOwnerLogEvent(ev EventRecord) error {
	if len(ev.ControllerSignatures()) == 0 {
		return fmt.Errorf("an owner log event is kept only with its signature")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("could not keep the owner log event: %w", err)
	}
	defer tx.Rollback()
	if err := takeTheWriteLock(tx); err != nil {
		return fmt.Errorf("could not keep the owner log event: %w", err)
	}
	var reserved string
	switch err := tx.QueryRow(`SELECT event_bytes_b64 FROM owner_log_reservations WHERE owner_aid = ? AND seq_num = ?`,
		ev.AID, ev.SequenceNumber).Scan(&reserved); {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("sequence number %d of %s was never reserved, so no event is kept there",
			ev.SequenceNumber, ev.AID)
	case err != nil:
		return fmt.Errorf("could not read the reservation: %w", err)
	}
	if reserved != ev.RawBytesB64 {
		return fmt.Errorf("sequence number %d of %s is reserved for a different event", ev.SequenceNumber, ev.AID)
	}
	var kept string
	switch err := tx.QueryRow(`SELECT raw_bytes_b64 FROM kel WHERE aid = ? AND seq_num = ?`,
		ev.AID, ev.SequenceNumber).Scan(&kept); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("could not read the owner identity's key log: %w", err)
	case kept != ev.RawBytesB64:
		return fmt.Errorf("a different event is already kept at sequence number %d of %s", ev.SequenceNumber, ev.AID)
	}
	if err := saveEvent(tx, ev); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE owner_log_reservations SET state = ? WHERE owner_aid = ? AND seq_num = ?`,
		OwnerLogDone, ev.AID, ev.SequenceNumber); err != nil {
		return fmt.Errorf("could not mark the reservation done: %w", err)
	}
	return tx.Commit()
}

// takeTheWriteLock makes a transaction's first act a write, so it holds the
// database's write lock before it reads anything.
//
// A transaction begins by reading, and under write-ahead logging what it
// reads is a snapshot. If another connection commits after that snapshot is
// taken, SQLite refuses the transaction's first write at once (SQLITE_BUSY,
// extended code 517) without waiting the busy timeout, because the snapshot
// can no longer be brought forward. With the lock taken first, another writer
// waits for it as busy_timeout says, and what the transaction reads is what
// it writes against. The statement changes no row.
func takeTheWriteLock(tx *sql.Tx) error {
	_, err := tx.Exec(`UPDATE owner_log_reservations SET state = state WHERE 0`)
	return err
}

// durably runs do in a transaction that is on disk when this returns nil.
//
// The store's connections journal by write-ahead log with synchronous=NORMAL
// (sqlitedb), under which a committed transaction survives the process ending
// and can be lost when the machine loses power: the log is not flushed at
// each commit. A reservation must outlive both, because the signature made
// after it does. So this one transaction runs with synchronous=FULL, which
// flushes the log at commit on every platform, and with fullfsync, which on
// Apple systems makes that flush reach the disk and elsewhere changes nothing.
// The connection is given back with the settings it had.
func (s *SQLiteStore) durably(do func(tx *sql.Tx) error) error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("could not open a durable transaction: %w", err)
	}
	defer conn.Close()
	// Read, then set, outside the transaction: SQLite ignores a change to
	// synchronous inside one.
	var hadSync, hadFull int
	if err := conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&hadSync); err != nil {
		return fmt.Errorf("could not open a durable transaction: %w", err)
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA fullfsync").Scan(&hadFull); err != nil {
		return fmt.Errorf("could not open a durable transaction: %w", err)
	}
	defer conn.ExecContext(ctx, fmt.Sprintf("PRAGMA fullfsync=%d", hadFull))
	defer conn.ExecContext(ctx, fmt.Sprintf("PRAGMA synchronous=%d", hadSync))
	for _, pragma := range []string{"PRAGMA synchronous=FULL", "PRAGMA fullfsync=ON"} {
		if _, err := conn.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("could not open a durable transaction: %w", err)
		}
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("could not open a durable transaction: %w", err)
	}
	defer tx.Rollback()
	if err := takeTheWriteLock(tx); err != nil {
		return fmt.Errorf("could not open a durable transaction: %w", err)
	}
	if err := do(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("the transaction was not written to disk: %w", err)
	}
	return nil
}
