package addon

import (
	"identity-agent-core/backup"
	"identity-agent-core/server"
)

// What an add-on reads of a backup without a key: the sizes in a backup file, the most epochs and slots the
// backup Host calls take, and the errors they answer with. They are the core's own (packages backup and
// server); an add-on need not import package backup or server, which derive and load keys, so it reads them here.
const (
	BackupFileIDLen = backup.FileIDLen
	BackupSlotLen   = backup.SlotLen
	BackupKeyLen    = backup.X25519KeyLen
	// MaxBackupEpoch is the highest epoch of a utility app's backup key.
	MaxBackupEpoch = server.MaxBackupEpoch
)

var (
	// ErrNoBackupSeed is that this Identity Agent holds no root seed of its own identity to derive a backup key from.
	ErrNoBackupSeed = server.ErrNoBackupSeed
	// ErrBackupAsked is that a backup call named an epoch, a length or a count outside what a backup has.
	ErrBackupAsked = server.ErrBackupAsked
)
