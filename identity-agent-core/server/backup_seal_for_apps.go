package server

import (
	"bytes"
	"errors"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

// The key a utility app's backups are sealed to, kept in the core.
//
// A utility app seals its backups to a public key and cannot read them back. The key is the
// Identity Agent's, one per utility app and epoch (backup.DeriveAppSealKeypair), made from the root seed here and never
// stored. An add-on that shows the key, or opens a backup for the owner, asks the core: it gets the public key,
// or the result of the opening sealed to a key the core derives or the restore key the owner approved, and never
// the seed, a private key, or the content key.
//
// What that is worth, said plainly: the seed comes back from the Identity Agent's own archive, which is sealed to
// its signers, so any signer, one removed since, and whoever runs this machine can derive every app's key offline.
// What these calls keep from an add-on is the online route: a bug in an add-on cannot leak the root the identity's
// own signing and pre-rotated keys come from.

const (
	// MaxBackupEpoch is the highest epoch of an app's key the core derives. An epoch moves only by the owner's
	// action, and every call that walks epochs does a derivation for each, so a huge one is refused, not walked.
	MaxBackupEpoch = 1024
	// maxBackupSlots is the most slots a file has (its count is one byte).
	maxBackupSlots = 255
)

// ErrBackupAsked is that what was asked for is outside what a backup has: an epoch of 0 or past MaxBackupEpoch, a
// file identifier or a key of the wrong length, or more than 255 slots.
var ErrBackupAsked = errors.New("not a backup request the core can answer")

// ErrNoBackupSeed is that this Identity Agent holds no root seed of its own identity to derive a backup key from.
var ErrNoBackupSeed = errors.New("this Identity Agent holds no root seed of its own identity to derive a backup key from")

// backupSeed is the root seed this Identity Agent's own identity was made from, and nothing else: with no seed
// there is no key.
//
// It also checks whose seed it is. A root seed file may be a person's identity or the machine's own, and a key
// derived from the wrong one is neither the Identity Agent's nor recoverable from its archive. So the seed is
// accepted only if the identity records a signing key and that seed derives it (identitySigningSeedFrom). An identity whose
// keys are held on another device, or were made elsewhere, fails the check and gets no backup key.
//
// The presence check is here because identitySigningSeedFrom compares the derived key with the published one only
// when the identity records one, so an identity with no recorded key would pass with any seed. The seed is loaded
// first, and by LoadRootSeed, which creates nothing: keyCanSign would make a device-local seed on a machine with
// none, and asking for a backup key must not leave one behind.
func (s *CoreServer) backupSeed() ([]byte, error) {
	seed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil || len(seed) < 32 {
		return nil, ErrNoBackupSeed
	}
	id, err := s.DataStore.GetIdentity()
	if err != nil || id == nil || id.PublicKey == "" {
		return nil, ErrNoBackupSeed
	}
	// The seed loaded above is the one checked, so no second read can make a seed of its own.
	if _, err := identitySigningSeedFrom(id, seed); err != nil {
		return nil, ErrNoBackupSeed
	}
	return seed, nil
}

// backupSealKeyOf is the public key an app's backups are sealed to at an epoch.
func (s *CoreServer) backupSealKeyOf(appAID string, epoch uint32) ([]byte, error) {
	if epoch == 0 || epoch > MaxBackupEpoch {
		return nil, ErrBackupAsked
	}
	seed, err := s.backupSeed()
	if err != nil {
		return nil, err
	}
	_, pub, err := backup.DeriveAppSealKeypair(seed, appAID, epoch)
	return pub, err
}

// openBackupSlot tries every slot under the app's keys, its epoch maxEpoch first and then each earlier one, and
// returns the content key and which slot opened. The content key stays in this file's callers.
func (s *CoreServer) openBackupSlot(appAID string, maxEpoch uint32, fileID []byte, slots [][]byte) (bek []byte, index int, err error) {
	if maxEpoch == 0 || maxEpoch > MaxBackupEpoch || len(fileID) != backup.FileIDLen || len(slots) > maxBackupSlots {
		return nil, 0, ErrBackupAsked
	}
	seed, err := s.backupSeed()
	if err != nil {
		return nil, 0, err
	}
	for e := maxEpoch; e >= 1; e-- {
		priv, _, err := backup.DeriveAppSealKeypair(seed, appAID, e)
		if err != nil {
			return nil, 0, err
		}
		for i, sl := range slots {
			if len(sl) != backup.SlotLen {
				continue
			}
			if k, err := backup.UnsealBEKForFile(priv, sl[:32], sl[44:], sl[32:44], fileID); err == nil {
				return k, i, nil
			}
		}
	}
	return nil, 0, ErrNoBackupSlotOpens
}

// ErrNoBackupSlotOpens is that no slot of the file opens under any key of the app up to the epoch given.
var ErrNoBackupSlotOpens = errors.New("no slot opens under this utility app's keys")

// backupSlotOpens says which slot of a file one of an app's keys opens, if any, without giving anything out of it.
func (s *CoreServer) backupSlotOpens(appAID string, maxEpoch uint32, fileID []byte, slots [][]byte) (int, bool, error) {
	_, i, err := s.openBackupSlot(appAID, maxEpoch, fileID, slots)
	switch {
	case err == nil:
		return i, true, nil
	case errors.Is(err, ErrNoBackupSlotOpens):
		return 0, false, nil
	}
	return 0, false, err
}

// resealBackupSlot opens the file's slot under the app's keys and makes a new slot for the key of toAppAID at
// toEpoch, bound to the same file. The core derives that key itself: the content key only ever goes to a key it holds.
func (s *CoreServer) resealBackupSlot(appAID string, maxEpoch uint32, fileID []byte, slots [][]byte, toAppAID string, toEpoch uint32) ([]byte, error) {
	if toEpoch == 0 || toEpoch > MaxBackupEpoch {
		return nil, ErrBackupAsked
	}
	bek, _, err := s.openBackupSlot(appAID, maxEpoch, fileID, slots)
	if err != nil {
		return nil, err
	}
	toPub, err := s.backupSealKeyOf(toAppAID, toEpoch)
	if err != nil {
		return nil, err
	}
	return backup.SealSlotForFile(toPub, bek, fileID)
}

// sealBackupOpenReply opens the file's slot under the app's keys and seals the content key to restoreKey for the
// request whose digest this is. It returns which slot opened.
func (s *CoreServer) sealBackupOpenReply(appAID string, maxEpoch uint32, fileID []byte, slots [][]byte, restoreKey, digest []byte) ([]byte, int, error) {
	// A reply sealed to a key this Identity Agent holds could be read by whoever holds that key, which is the thing a
	// restore key is for not being.
	if s.isOwnBackupSealKey(restoreKey, map[string]uint32{appAID: maxEpoch}) {
		return nil, 0, ErrBackupAsked
	}
	bek, i, err := s.openBackupSlot(appAID, maxEpoch, fileID, slots)
	if err != nil {
		return nil, 0, err
	}
	reply, err := backup.SealOpenReply(restoreKey, bek, digest)
	return reply, i, err
}

// isOwnBackupSealKey is whether pub is a key this Identity Agent can open backups with: the person's key from the
// seed, or the key of any app named in epochs (app identifier to the epoch it is at) at that epoch or an earlier one.
// A restore key must be none of them. With no seed it says true, so a caller that needs "not ours" fails closed.
func (s *CoreServer) isOwnBackupSealKey(pub []byte, epochs map[string]uint32) bool {
	if len(pub) != backup.X25519KeyLen {
		return true
	}
	seed, err := s.backupSeed()
	if err != nil {
		return true
	}
	if _, mine, err := backup.DeriveSealKeypair(seed); err != nil || bytes.Equal(mine, pub) {
		return true
	}
	for app, cur := range epochs {
		if cur > MaxBackupEpoch {
			return true
		}
		for e := uint32(1); e <= cur; e++ {
			_, k, err := backup.DeriveAppSealKeypair(seed, app, e)
			if err != nil {
				return true
			}
			if bytes.Equal(k, pub) {
				return true
			}
		}
	}
	return false
}
