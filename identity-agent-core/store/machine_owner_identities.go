package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// An identity minted for a machine that does not exist yet.
//
// The machine is told who may claim it before it starts, so its owner has to be
// minted first. All that must survive until adoption is the INDEX: the key is
// derived from this device's seed at that index, and without it the identity
// can never sign, rotate or revoke again.
//
// Kept here rather than handed to the caller and taken back, because a caller
// that supplied it would have to be trusted or checked, and neither is needed
// when this side minted it in the first place.

// MachineOwnerIdentity is an owner identity as this device keeps it: where its
// key comes from, and what its key log cannot say (ADR-087).
type MachineOwnerIdentity struct {
	AID      string
	KeyIndex int
	// Kind is what it was minted to own, stored at mint: "individual" for a
	// person's own machine, "organisation" for an organisation's Identity
	// Agent, or empty where the mint did not say.
	Kind string
	// AnchoredM is the one Identity Agent its log anchors, or empty.
	AnchoredM string
	// GivenUpFor is the Identity Agent it was given up for, or empty. A
	// given-up owner identity never anchors or signs an owner request again.
	GivenUpFor string
	// DuplicitousAt is the first sequence number at which two events of its
	// log are known, or nil.
	DuplicitousAt *int
}

// RememberMachineOwnerIdentity records where a minted identity's key came
// from and what it was minted to own. The kind is stored once, at mint: a
// second call for the same identity changes nothing.
func (s *SQLiteStore) RememberMachineOwnerIdentity(aid string, keyIndex int, kind string) error {
	if aid == "" || keyIndex <= 0 {
		return fmt.Errorf("a machine owner identity needs both an identifier and the index its key came from")
	}
	_, err := s.db.Exec(`
		INSERT INTO machine_owner_identities (aid, key_index, kind) VALUES (?, ?, ?)
		ON CONFLICT(aid) DO NOTHING
	`, aid, keyIndex, kind)
	if err != nil {
		return fmt.Errorf("could not remember the machine owner identity: %w", err)
	}
	return nil
}

// MachineOwnerIndex returns where a minted identity's key came from.
//
// Reports whether it was found rather than returning zero, because zero is a
// real-looking index and a caller that treated it as one would derive the wrong
// key and adopt a machine nobody could speak to.
func (s *SQLiteStore) MachineOwnerIndex(aid string) (int, bool, error) {
	id, found, err := s.MachineOwnerIdentity(aid)
	return id.KeyIndex, found, err
}

const machineOwnerColumns = `aid, key_index, kind, anchored_m, given_up_for, duplicitous_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanMachineOwner(r rowScanner) (MachineOwnerIdentity, error) {
	var id MachineOwnerIdentity
	var dup sql.NullInt64
	if err := r.Scan(&id.AID, &id.KeyIndex, &id.Kind, &id.AnchoredM, &id.GivenUpFor, &dup); err != nil {
		return id, err
	}
	if dup.Valid {
		at := int(dup.Int64)
		id.DuplicitousAt = &at
	}
	return id, nil
}

// MachineOwnerIdentity returns everything kept about a minted owner identity,
// and whether this device minted it.
func (s *SQLiteStore) MachineOwnerIdentity(aid string) (MachineOwnerIdentity, bool, error) {
	return machineOwnerIdentity(s.db, aid)
}

func machineOwnerIdentity(q interface {
	QueryRow(string, ...any) *sql.Row
}, aid string) (MachineOwnerIdentity, bool, error) {
	id, err := scanMachineOwner(q.QueryRow(
		`SELECT `+machineOwnerColumns+` FROM machine_owner_identities WHERE aid = ?`, aid))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MachineOwnerIdentity{}, false, nil
		}
		return MachineOwnerIdentity{}, false, fmt.Errorf("could not read the machine owner identity: %w", err)
	}
	return id, true, nil
}

// MachineOwnerIdentities lists every owner identity this device minted, in
// the order of the index their keys come from.
func (s *SQLiteStore) MachineOwnerIdentities() ([]MachineOwnerIdentity, error) {
	rows, err := s.db.Query(`SELECT ` + machineOwnerColumns + ` FROM machine_owner_identities ORDER BY key_index`)
	if err != nil {
		return nil, fmt.Errorf("could not list the machine owner identities: %w", err)
	}
	defer rows.Close()
	var out []MachineOwnerIdentity
	for rows.Next() {
		id, err := scanMachineOwner(rows)
		if err != nil {
			return nil, fmt.Errorf("could not read a machine owner identity: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// GiveUpMachineOwnerIdentity records that an owner identity was given up, and
// for which Identity Agent (ADR-087 decision 7). It is never undone, and an
// identity already given up for another Identity Agent is refused.
func (s *SQLiteStore) GiveUpMachineOwnerIdentity(aid, m string) error {
	if m == "" {
		return fmt.Errorf("an owner identity is given up for a named Identity Agent")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := takeTheWriteLock(tx, "machine_owner_identities"); err != nil {
		return err
	}
	id, found, err := machineOwnerIdentity(tx, aid)
	if err != nil {
		return err
	}
	switch {
	case !found:
		return fmt.Errorf("this device did not mint %s", aid)
	case id.AnchoredM != "" && id.AnchoredM != m:
		return fmt.Errorf("%s anchors %s, so it cannot be given up for %s", aid, id.AnchoredM, m)
	case id.GivenUpFor != "" && id.GivenUpFor != m:
		return fmt.Errorf("%s was already given up for %s", aid, id.GivenUpFor)
	}
	if _, err := tx.Exec(`UPDATE machine_owner_identities SET given_up_for = ? WHERE aid = ?`, m, aid); err != nil {
		return fmt.Errorf("could not record that the owner identity was given up: %w", err)
	}
	return tx.Commit()
}

// MarkMachineOwnerIdentityDuplicitous records the first sequence number at
// which two events of an owner identity's log are known. An earlier place
// replaces a later one, and nothing clears it.
func (s *SQLiteStore) MarkMachineOwnerIdentityDuplicitous(aid string, sn int) error {
	res, err := s.db.Exec(`UPDATE machine_owner_identities
		SET duplicitous_at = MIN(COALESCE(duplicitous_at, ?), ?) WHERE aid = ?`, sn, sn, aid)
	if err != nil {
		return fmt.Errorf("could not record the duplicity: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("this device did not mint %s", aid)
	}
	return nil
}
