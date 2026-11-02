package secureenclave

import (
	"errors"

	"identity-agent-core/buildmode"
)

// A PERSON'S ROOT SEED AND A MACHINE'S OWN SEED ARE DIFFERENT THINGS.
//
// The root seed of an identity is what the person's recovery phrase
// reproduces. Whoever copies it becomes that identity, permanently, with
// nothing to detect it and no rotation that undoes it. The device-local seed
// EnsureRootSeed makes for a machine belongs to nobody and is recovered from
// that machine's own backup.
//
// They used to go through one function that quietly fell back to a plain
// base64 file when no wrapper was available, and four of the five callers never
// asked whether this machine could protect what they were writing. Now there
// are two functions with two names:
//
//   - StoreIdentityRootSeed — the person's root. Refuses, before writing
//     anything, unless this machine can protect it; and can never produce the
//     plaintext envelope outside a development build.
//   - StoreDeviceLocalSeed — the machine's own. May be stored unwrapped.
//
// The check lives here rather than in each caller because a check in the
// caller is a convention, and the root-seed route was the only one that kept it.

// ErrRootSeedCannotLiveHere is the refusal: this machine cannot protect a
// person's root seed, so none was written.
type ErrRootSeedCannotLiveHere struct {
	Capability Capability
	Reason     string
}

func (e *ErrRootSeedCannotLiveHere) Error() string {
	msg := "this machine cannot protect an identity's root seed, so none was written: " + e.Reason
	if e.Capability.Status != "" {
		msg += " (" + e.Capability.String() + ")"
	}
	return msg + ". Recover onto a device with usable key protection, or pair this machine to one"
}

// detectCapability is the machine's answer behind a seam, so the refusal and the
// permitted case can both be tested on any host.
var detectCapability = DetectCapability

// UseCapabilityDetector replaces how this package asks what the machine can
// protect a key with, and returns a function that puts the real one back. For
// tests and for an embedding app that knows better than the build (Android
// reports its keystore this way).
func UseCapabilityDetector(f func() Capability) (restore func()) {
	prev := detectCapability
	detectCapability = f
	return func() { detectCapability = prev }
}

// UseSeedWrapper replaces the platform seed wrapper and returns a function that
// puts the real one back. For tests and for an embedding app that supplies its
// own keystore-backed wrapper.
func UseSeedWrapper(w SeedWrapper) (restore func()) {
	prev := platformSeedWrapper
	platformSeedWrapper = func() SeedWrapper { return w }
	return func() { platformSeedWrapper = prev }
}

// rootSeedMayLiveHere is the decision, pure so every combination can be tested.
// A production build needs proven-usable hardware AND a wrapper that is working;
// a development build is exempt, exactly as the root-seed route's gate is
// (the identity it admits is a development-realm one).
func rootSeedMayLiveHere(cap Capability, wrapperWorks, dev bool) bool {
	return dev || (cap.RootKeyPermitted() && wrapperWorks)
}

// CheckRootSeedMayLiveHere asks whether a person's root seed may be written on
// this machine, without writing anything. Callers that have work to do before
// the write (recovery restores files first) ask this first so a refusal
// touches nothing.
func CheckRootSeedMayLiveHere() error {
	cap := detectCapability()
	w := platformSeedWrapper()
	works := w != nil && w.Available()
	if rootSeedMayLiveHere(cap, works, buildmode.IsDev()) {
		return nil
	}
	reason := "its key protection is not proven usable"
	if cap.RootKeyPermitted() {
		reason = "key hardware is usable but " + whyNotWrapped()
	}
	return &ErrRootSeedCannotLiveHere{Capability: cap, Reason: reason}
}

// StoreIdentityRootSeed persists a person's root seed. It refuses, having
// written nothing, where the machine cannot protect it; and outside a
// development build it cannot write the plaintext envelope at all.
func StoreIdentityRootSeed(dataDir string, seed []byte) error {
	if err := CheckRootSeedMayLiveHere(); err != nil {
		return err
	}
	// Production: a wrapper is mandatory, so the check inside storeSeed is a
	// second, independent lock on the same door.
	return storeSeed(dataDir, seed, platformSeedWrapper(), !buildmode.IsDev())
}

// IsRootSeedRefusal reports whether err is the refusal above.
func IsRootSeedRefusal(err error) bool {
	var e *ErrRootSeedCannotLiveHere
	return errors.As(err, &e)
}
