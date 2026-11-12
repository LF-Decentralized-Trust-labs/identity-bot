package secureenclave

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// THE GATE LAYER OF A STORED SEED (ADR-074 section 2).
//
//	envelope = HardwareWrap_device( GateSeal_GK( seed ) )
//
// This package does not know what GK is or who releases it: it is told, per data
// directory, whether the profile there is gated and, if so, holds a sealer that
// is present only while the identity is open. A locked identity has no sealer,
// so no seed is read or written and nothing is derived from it.

// ErrIdentityLocked is the answer for anything that needs a gated profile's
// seed while the profile is locked.
var ErrIdentityLocked = errors.New("identity is locked")

// GateSealer seals and opens under the key the gate released.
type GateSealer interface {
	Seal(plain []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// gateScheme is recorded in an envelope sealed under a gate.
const gateScheme = "gk-aes256gcm-v1"

// gateOf answers, for a data directory: is its profile gated, and if so the
// sealer while it is open (nil while locked). Nil means no profile is gated.
var gateOf = func(dataDir string) (GateSealer, bool) { return nil, false }

// UseGate installs the lookup a gate implementation provides, and returns the
// function that puts the previous one back.
func UseGate(f func(dataDir string) (GateSealer, bool)) (restore func()) {
	prev := gateOf
	gateOf = f
	return func() { gateOf = prev }
}

// ErrGateRequired is the refusal to store a seed, or a secret that reproduces
// one, in a profile this build requires a gate for and which has none: making
// the gate failed, and storing under no gate now would leave the identity
// unlockable-by-nothing forever.
var ErrGateRequired = errors.New("this identity must have a gate before it stores a secret, and its gate could not be made")

// gateRequiredFor says a profile must be gated before anything is stored in it.
var gateRequiredFor = func(dataDir string) bool { return false }

// UseGateRequirement installs the lookup that says which profiles must have a
// gate before a seed is stored, and returns the function that undoes it.
func UseGateRequirement(f func(dataDir string) bool) (restore func()) {
	prev := gateRequiredFor
	gateRequiredFor = f
	return func() { gateRequiredFor = prev }
}

// theGateForThisSeedToStore is theGateForThisSeed for a write: a profile that
// must be gated and is not refuses.
func theGateForThisSeedToStore(dataDir string) (GateSealer, bool, error) {
	s, gated, err := theGateForThisSeed(dataDir)
	if err == nil && !gated && gateRequiredFor(dataDir) {
		return nil, false, ErrGateRequired
	}
	return s, gated, err
}

// theGateForThisSeed is the sealer to use, or ErrIdentityLocked when the profile
// is gated and not open.
func theGateForThisSeed(dataDir string) (s GateSealer, gated bool, err error) {
	s, gated = gateOf(dataDir)
	if gated && s == nil {
		return nil, true, ErrIdentityLocked
	}
	return s, gated, nil
}

// ReSealRootSeed replaces the gate layer of a stored seed: it opens the seed
// with open and seals it with seal. For changing the optional identity secret
// (the key that seals the profile changes) and for moving a profile under a gate.
// Nothing is changed unless the new envelope is written whole.
func ReSealRootSeed(dataDir string, open, seal func([]byte) ([]byte, error)) error {
	env, err := readEnvelope(dataDir)
	if err != nil {
		return err
	}
	blob, err := base64.StdEncoding.DecodeString(env.Blob)
	if err != nil {
		return fmt.Errorf("root seed envelope corrupt: %w", err)
	}
	if env.Wrap != seedWrapNone {
		w := platformSeedWrapper()
		if w == nil || !wrapperOpensScheme(w, env.Wrap) {
			return fmt.Errorf("root seed is wrapped with %q, which this build cannot open", env.Wrap)
		}
		if blob, err = w.Unwrap(blob); err != nil {
			return fmt.Errorf("root seed unwrap failed: %w", err)
		}
	}
	seed := blob
	if env.Gate != "" {
		if seed, err = open(blob); err != nil {
			return fmt.Errorf("root seed does not open under the current gate key: %w", err)
		}
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	return storeSeedSealedBy(dataDir, seed, platformSeedWrapper(), !isDevBuild(), holderOfStoredSeed(dataDir), seal)
}

func holderOfStoredSeed(dataDir string) string {
	if env, err := readEnvelope(dataDir); err == nil {
		return env.Holder
	}
	return ""
}

func gateSchemeOf(env seedEnvelope) bool { return env.Gate == gateScheme }

func errGateUnknown(env seedEnvelope) error {
	return fmt.Errorf("root seed is sealed under gate scheme %q, which this build cannot open", env.Gate)
}

// TheStoredSeedIsUnderAGate says the seed stored at dataDir is a version 2
// envelope sealed under a gate layer. Such a profile is gated whatever else is
// on disk: a gate record that has gone missing means locked or broken, never
// "made before locking existed" (ADR-074).
func TheStoredSeedIsUnderAGate(dataDir string) bool {
	env, err := readEnvelope(dataDir)
	return err == nil && env.V >= 2 && env.Gate != ""
}
