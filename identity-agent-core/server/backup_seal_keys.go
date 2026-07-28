package server

// Publishing the key a device seals its backups to.
//
// A device that has just been adopted holds a delegated identity and no way to
// protect what it is about to accumulate. It could ask for a seed phrase — and
// that is exactly the thing worth not doing, because a machine given a phrase
// can act as its owner forever and cannot be un-given it.
//
// So the owner hands over a public key instead. The adopted device seals a
// random backup key to it, keeps nothing, and can write archives it has no way
// to read. Recovery still needs only the owner's phrase, because the private
// half comes from the same seed those words produce and never leaves the
// owner's device.
//
// Two directions live here. Deriving what to send is the owner's side;
// recording what arrived is the adopted device's side. They are together
// because they are two halves of one exchange, and separating them is how the
// two ends drift apart.

import (
	"fmt"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

// ownerBackupSealPublicKeys returns the public keys an adopted device should
// seal its backups to — this owner's, derived from the root seed held here.
//
// It returns a list because an organisation has one owner per signer, and any
// of them must be able to restore the company's data alone. Today that list
// has one entry; the shape is here so adding signers does not change the wire.
func (s *CoreServer) ownerBackupSealPublicKeys() ([]string, error) {
	seed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("no root seed on this device, so there is nothing to derive a recovery key from: %w", err)
	}
	pub, err := backup.DeriveSealPublicKey(seed)
	if err != nil {
		return nil, err
	}
	return []string{backup.EncodeB64(pub)}, nil
}

// recordBackupSealKeys stores the keys this device will seal its backups to.
//
// Every key is validated before any is stored. A key that is malformed here
// becomes an archive nobody can open, and that is only discovered on the day
// somebody needs it — so a bad key is refused now, loudly, rather than written
// down and trusted later.
func (s *CoreServer) recordBackupSealKeys(keysB64 []string) error {
	if len(keysB64) == 0 {
		return fmt.Errorf("no recovery keys given")
	}
	for i, encoded := range keysB64 {
		raw, err := backup.DecodeB64(encoded)
		if err != nil {
			return fmt.Errorf("recovery key %d is not valid base64: %w", i, err)
		}
		if len(raw) != backup.X25519KeyLen {
			return fmt.Errorf("recovery key %d must be %d bytes, got %d", i, backup.X25519KeyLen, len(raw))
		}
	}

	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		return fmt.Errorf("load backup config: %w", err)
	}
	cfg.SealToPublicKeysB64 = keysB64
	return s.backupService().SaveConfig(cfg)
}
