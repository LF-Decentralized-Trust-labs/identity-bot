package secureenclave

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
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
//
//     CORRECTED 2026-08-31: that is the intent and it is not what happens. Only
//     darwin arm64 with cgo has a wrapper at all, and on macOS it cannot persist
//     its key because a nested helper binary carries no keychain entitlement —
//     so the seed is stored in the clear on every target but iOS, and the file
//     alone is exactly as useful off-device as the seed. Reported rather than
//     refused, because writing the wrappers is our work and not a fault in
//     anybody's hardware; announceIfStoredInTheClear below is what says so.
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

// SeedWrapAvailable reports whether this platform can actually wrap the root
// seed under a hardware-held key, right now, in this process.
//
// It exists so that anything telling a user their keys are hardware-protected
// has to ask the code that would do the protecting, rather than inferring it
// from a device node being present. Those are different questions: a TPM chip
// can be installed and usable while nothing whatsoever is wrapped by it, which
// is exactly the state a platform is in before its wrapper is written.
//
// A false security indicator is worse than an absent one, because it is the one
// somebody relies on.
func SeedWrapAvailable() bool {
	w := platformSeedWrapper()
	return w != nil && w.Available()
}

// SeedWrapScheme names the wrap format in use, or "none" when the seed is
// stored unwrapped. Returned alongside the boolean so a caller can say WHY
// rather than only that.
func SeedWrapScheme() string {
	w := platformSeedWrapper()
	if w == nil || !w.Available() {
		return seedWrapNone
	}
	return w.Scheme()
}

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

// unwrappedSeedWarning holds the unwrapped-seed line to one per process.
var unwrappedSeedWarning sync.Once

// whyNotWrapped names which of the two gaps this build has, because the remedy
// differs entirely: a wrapper nobody has written yet, or one that is there and
// cannot get at the hardware.
func whyNotWrapped() string {
	w := platformSeedWrapper()
	switch {
	case w == nil:
		return "no seed wrapper is compiled in for this platform"
	case !w.Available():
		return "the " + w.Scheme() + " wrapper is compiled in and cannot use the hardware"
	default:
		return "the " + w.Scheme() + " wrapper is available and this seed was not put through it"
	}
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

	// SAY WHICH ONE HAPPENED. Storing wrapped and storing in the clear look
	// identical from outside this function, and the second is the failure
	// everything upstream exists to prevent — so a machine that could have
	// protected this seed and did not says so, once, at the moment it does it.
	//
	// The two questions are different and both are asked here. DetectCapability
	// answers whether the HARDWARE can protect a key; the wrapper answers
	// whether THIS BUILD uses it to protect the seed. A machine can pass the
	// first and fail the second, which is the case this warns about: our gap,
	// on somebody's hardware, and silent until now.
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
	if err := os.Rename(tmp, p); err != nil {
		return err
	}

	// AFTER THE SEED IS ON DISK, AND ONLY THEN.
	//
	// This was a defer, which ran on every exit — including the wrap failure,
	// the round-trip failure and both write failures, where env.Wrap is still
	// "none" and nothing was written. So it announced an unwrapped seed for a
	// store that never happened; and because the warning is held to one per
	// process, that false line was the only one the process would ever emit,
	// silencing the real unwrapped store that came next. A warning that lies
	// and then silences itself is worse than no warning, which is the thing
	// this whole line exists to say about a seed in the clear.
	announceIfStoredInTheClear(env.Wrap)
	return nil
}

// announceIfStoredInTheClear says, once per process, that a machine which could
// have protected this seed did not.
//
// Once rather than per store: a line printed for the rest of a machine's life
// teaches whoever reads the log to skip it, and this is the line that must not
// be skipped — ask_sign_layer.go records the same reasoning for the same
// reason. Once also keeps the cost bearable, since answering means asking the
// hardware and a seed can be stored on a hot path during recovery.
func announceIfStoredInTheClear(wrap string) {
	if wrap != seedWrapNone {
		return
	}
	unwrappedSeedWarning.Do(func() {
		cap := DetectCapability()
		if !cap.RootKeyPermitted() {
			return
		}
		log.Printf("[keystore] this machine can protect a key (%s) and this build did "+
			"not use it: the root seed is stored UNWRAPPED. Anyone who reads the file "+
			"becomes this identity, permanently and undetectably. The hardware is not "+
			"the gap here — %s", cap.String(), whyNotWrapped())
	})
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
