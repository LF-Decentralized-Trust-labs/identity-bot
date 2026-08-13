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

// RememberMachineOwnerIdentity records where a minted identity's key came from.
func (s *SQLiteStore) RememberMachineOwnerIdentity(aid string, keyIndex int) error {
	if aid == "" || keyIndex <= 0 {
		return fmt.Errorf("a machine owner identity needs both an identifier and the index its key came from")
	}
	_, err := s.db.Exec(`
		INSERT INTO machine_owner_identities (aid, key_index) VALUES (?, ?)
		ON CONFLICT(aid) DO NOTHING
	`, aid, keyIndex)
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
	var idx int
	err := s.db.QueryRow(`SELECT key_index FROM machine_owner_identities WHERE aid = ?`, aid).Scan(&idx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("could not read the machine owner identity: %w", err)
	}
	return idx, true, nil
}
