package secureenclave

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
)

// EnsureRootSeed is this machine's root seed: the one stored, or, only where
// none has ever been stored, a new device-local one. A seed that is stored and
// cannot be read is never replaced, since replacing it destroys the only copy
// of every key derived from it. The one way every part of this agent obtains
// the root seed.
func EnsureRootSeed(dataDir string) ([]byte, error) {
	seed, err := LoadRootSeed(dataDir)
	if err == nil {
		return seed, nil
	}
	// Only a machine that has never held a seed gets one here. A seed that is
	// there and cannot be read (a damaged file, a wrapping this build cannot
	// open) is refused rather than replaced: replacing it would destroy the
	// only copy of every key derived from it.
	if !errors.Is(err, ErrNoRootSeed) {
		return nil, fmt.Errorf("this machine's root seed is stored but cannot be read, and is not replaced: %w", err)
	}
	// Said plainly, and no longer as a warning about something missing.
	//
	// For a computer that answers to somebody this IS the arrangement, not a
	// fallback waiting for a handoff: it holds its own key, its owner's root
	// stays on the device its owner carries, and there is no phrase for this
	// seed because it is not anybody's identity. It is in this machine's backup
	// archive, which is what recovers it.
	//
	// Calling that a warning for the rest of the machine's life would train
	// whoever reads the log to ignore the line — and it is the line that says
	// where recovery comes from.
	log.Printf("[keystore] this machine holds a device-local root seed of its own. Its keys " +
		"are recoverable from this machine's backup archive, and not from a seed phrase — " +
		"there is no phrase for it")
	seed = make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := StoreRootSeed(dataDir, seed); err != nil {
		return nil, fmt.Errorf("bootstrap root seed: %w", err)
	}
	// Written down, because nothing else can tell afterwards. This seed is
	// random and belongs to no identity, so an archive marked as though the
	// owner's words had written it is one they can never restore.
	if err := RecordSeedOrigin(dataDir, SeedIsDeviceLocal); err != nil {
		log.Printf("[keystore] could not record where this machine's root seed came from, "+
			"so its backups will be signed as this machine's rather than its owner's: %v", err)
	}
	return seed, nil
}
