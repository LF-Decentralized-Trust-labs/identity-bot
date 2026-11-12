package secureenclave

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// A WRAPPING KEY OF A PROFILE'S OWN (ADR-074 section 3, "per-profile key name").
//
// Until this, every profile on a device was wrapped under one hardware key: one
// Secure Enclave key on iOS, one TPM key on Windows, one Keystore key on
// Android. A device carries several people, and the hardware layer of one
// profile must not be the hardware layer of the others, so each platform's
// wrapper can now name a key per profile.
//
// What the name is for, by platform:
//
//	iOS      the keychain application tag of the Secure Enclave key
//	Android  the Keystore alias the app generates the key under
//	Windows  the persisted key's name inside the Platform Crypto Provider
//	macOS    nothing: the wrapper already makes a key per wrap and keeps its blob
//	         inside the wrapped bytes, so it is per profile by construction
//
// The name is recorded in what was wrapped (the seed envelope's "key", a held
// key's "wrap_key"), so a reader opens it under the key it was written under and
// never has to be told. Empty means the device-wide key that every envelope
// written before this used; it stays the key such an envelope opens with, and it
// is not deleted here (ADR-074 section 6: that is the one point of no return and
// it is its own, last, step).

// PerProfileKeys is what a platform wrapper implements to hold a key per
// profile. A wrapper that does not (the sealed-volume wrapper, a test double) is
// used device-wide, exactly as before.
type PerProfileKeys interface {
	// KeyNameFor is the name of the key for this profile, in this platform's own
	// naming. It is built by ProfileKeyName so that it has one spelling.
	KeyNameFor(profile string) string
	// ForKey is the wrapper that uses the key of that name, making it on first
	// use where the platform needs it made. It is a wrapper like the one it came
	// from in every other respect.
	ForKey(name string) SeedWrapper
}

// ProfileKeyName is the one spelling of a per-profile key name: the platform's
// base name, a dot, and a short digest of the profile id. The digest, not the
// id, so a name never carries a character a keychain tag, a Keystore alias or a
// TPM key name may refuse, and never grows with the id. 16 hex digits is 64
// bits: enough that two profiles on one device do not share a key, which is what
// is being kept apart; the name is not a secret.
func ProfileKeyName(base, profile string) string {
	sum := sha256.Sum256([]byte("identity-agent wrapping key of profile|" + profile))
	return base + ".p-" + hex.EncodeToString(sum[:8])
}

// profileOf says which profile owns the data directory, or "" when none has a
// gate there. It is installed by the gate, which is the one place that knows.
var profileOf = func(dataDir string) string { return "" }

// UseProfileLookup installs the lookup that names the profile of a data
// directory, and returns the function that puts the previous one back.
func UseProfileLookup(f func(dataDir string) string) (restore func()) {
	prev := profileOf
	profileOf = f
	return func() { profileOf = prev }
}

// wrapperAndKeyFor is the wrapper to write under for the profile at dataDir, and
// the key name to record. A profile with an id on a platform that holds a key per
// profile gets its own key; every other case gets base as it came, with no name.
func wrapperAndKeyFor(base SeedWrapper, dataDir string) (SeedWrapper, string) {
	return wrapperAndKeyForProfile(base, profileOf(dataDir))
}

func wrapperAndKeyForProfile(base SeedWrapper, profile string) (SeedWrapper, string) {
	pk, ok := base.(PerProfileKeys)
	if !ok || profile == "" {
		return base, ""
	}
	name := pk.KeyNameFor(profile)
	if name == "" {
		return base, "" // the platform has no key of its own to name
	}
	return pk.ForKey(name), name
}

// wrapperThatOpens is the wrapper that opens what was written under key: base
// for "" (the device-wide key), the platform's key of that name otherwise. A
// platform that cannot name keys cannot open one that was.
func wrapperThatOpens(base SeedWrapper, key string) (SeedWrapper, error) {
	if key == "" {
		return base, nil
	}
	pk, ok := base.(PerProfileKeys)
	if !ok {
		return nil, fmt.Errorf("this was wrapped under the per-profile key %q, which this platform cannot name", key)
	}
	return pk.ForKey(key), nil
}
