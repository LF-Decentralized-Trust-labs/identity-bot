package secureenclave

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Root-seed protection at rest.
//
// The root keystore seed is the derivation root for every HD key the agent mints
// (pairwise contact keys, login relationships, asset signing, audit signing) and
// for the credential-vault key. Two invariants govern how it is stored:
//
//  1. The seed's at-rest file is WRAPPED under a hardware-held key where the
//     platform has one (Secure Enclave today; TPM/StrongBox/TEE behind the same
//     seam later). The hardware key never leaves its element; the seed file alone
//     is useless off-device.
//  2. Hardware is a device-local confidentiality layer, NEVER part of recovery.
//     The seed is included (plaintext, inside the encrypted payload) in backup
//     archives, so recovery = mnemonic -> open archive -> reseat seed on the new
//     device, where it is re-wrapped under that device's own hardware key. Losing
//     the hardware key (or the whole device) must never lose anything a backup +
//     mnemonic cannot restore.
//
// Wrapping protects the file at rest — disk theft, file exfiltration, other-user
// reads. It does not (and cannot) protect against code running as the same user
// on the unlocked device; that is the OS trust boundary, addressed by code
// signing and sealed infrastructure, not by storage.

// SeedWrapper seals/opens the root seed under a platform-held key.
type SeedWrapper interface {
	// Available reports whether the platform key is usable in this process
	// (hardware present, process entitled). Checked at store time; when false the
	// seed is stored unwrapped, exactly as before this layer existed.
	Available() bool
	// Scheme names the wrap format, recorded in the envelope (e.g. "se-ecies-p256").
	Scheme() string
	Wrap(plain []byte) ([]byte, error)
	Unwrap(blob []byte) ([]byte, error)
}

// platformSeedWrapper is provided per-platform (nil where no hardware wrapper
// exists). Tests may override.
var platformSeedWrapper = newPlatformSeedWrapper

const seedWrapNone = "none"

// seedEnvelope is the self-describing on-disk form of root_seed.key. A legacy
// file (raw seed bytes, pre-envelope) is detected by failing to parse as this
// envelope and is migrated on first load.
type seedEnvelope struct {
	V    int    `json:"v"`
	Wrap string `json:"wrap"`
	Blob string `json:"blob"`
}

func rootSeedPath(dataDir string) string {
	return filepath.Join(dataDir, "secureenclave", "root_seed.key")
}

// StoreRootSeed persists the root keystore seed (64-byte BIP39-class seed),
// wrapped under the platform hardware key when one is usable.
func StoreRootSeed(dataDir string, seed []byte) error {
	if len(seed) < 32 {
		return fmt.Errorf("root seed must be at least 32 bytes")
	}
	toStore := seed
	if len(toStore) > 64 {
		toStore = toStore[:64]
	}

	env := seedEnvelope{V: 1, Wrap: seedWrapNone, Blob: base64.StdEncoding.EncodeToString(toStore)}
	if w := platformSeedWrapper(); w != nil && w.Available() {
		blob, err := w.Wrap(toStore)
		if err != nil {
			return fmt.Errorf("wrap root seed (%s): %w", w.Scheme(), err)
		}
		// Never trust a wrap we can't open: verify the round trip before the
		// wrapped form becomes the only copy on disk.
		back, err := w.Unwrap(blob)
		if err != nil || !bytes.Equal(back, toStore) {
			return fmt.Errorf("wrap verification failed (%s): %v", w.Scheme(), err)
		}
		env = seedEnvelope{V: 1, Wrap: w.Scheme(), Blob: base64.StdEncoding.EncodeToString(blob)}
	}

	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	p := rootSeedPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	// Atomic replace so a crash mid-write can never leave a corrupt (or half
	// plaintext) seed file.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LoadRootSeed reads the root keystore seed, unwrapping it when stored under a
// platform key. A legacy raw-bytes file is migrated to the envelope form (and
// wrapped, when hardware is usable) on first load.
func LoadRootSeed(dataDir string) ([]byte, error) {
	p := rootSeedPath(dataDir)
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("root keystore seed not available in secure storage: %w", err)
	}

	var env seedEnvelope
	if jerr := json.Unmarshal(raw, &env); jerr != nil || env.V < 1 || env.Wrap == "" {
		// Legacy pre-envelope file: the raw seed bytes themselves.
		if len(raw) < 32 {
			return nil, fmt.Errorf("invalid root seed size")
		}
		seed := raw
		if merr := StoreRootSeed(dataDir, seed); merr != nil {
			// Keep serving the legacy file rather than risk the only copy.
			log.Printf("[secureenclave] root seed migration deferred: %v", merr)
		} else {
			log.Printf("[secureenclave] root seed migrated to envelope storage")
		}
		return seed, nil
	}

	blob, err := base64.StdEncoding.DecodeString(env.Blob)
	if err != nil {
		return nil, fmt.Errorf("root seed envelope corrupt: %w", err)
	}
	if env.Wrap == seedWrapNone {
		if len(blob) < 32 {
			return nil, fmt.Errorf("invalid root seed size")
		}
		// Opportunistic upgrade: if hardware became usable since the seed was
		// stored (e.g. a signed build replacing a dev build), wrap it now.
		if w := platformSeedWrapper(); w != nil && w.Available() {
			if merr := StoreRootSeed(dataDir, blob); merr != nil {
				log.Printf("[secureenclave] root seed wrap upgrade deferred: %v", merr)
			} else {
				log.Printf("[secureenclave] root seed upgraded to %s wrapping", w.Scheme())
			}
		}
		return blob, nil
	}

	w := platformSeedWrapper()
	if w == nil || w.Scheme() != env.Wrap {
		return nil, fmt.Errorf("root seed is wrapped with %q, which this build/platform cannot open — restore from a backup archive with the seed phrase", env.Wrap)
	}
	seed, err := w.Unwrap(blob)
	if err != nil {
		return nil, fmt.Errorf("root seed unwrap failed (%s) — the device key may be gone; restore from a backup archive with the seed phrase: %w", env.Wrap, err)
	}
	if len(seed) < 32 {
		return nil, fmt.Errorf("invalid root seed size after unwrap")
	}
	return seed, nil
}
