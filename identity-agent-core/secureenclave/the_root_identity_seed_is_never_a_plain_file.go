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
	// Phone is set when the machine is a phone, whose refusal is worded for the
	// person holding it (PhoneHardwareUnavailable) rather than for an operator.
	Phone bool
}

// PhoneHardwareUnavailable is what a phone's owner is told when the app cannot
// yet put the root seed under the phone's StrongBox or TEE key. It is the
// sentence an app may show as it stands; Error() carries the technical reason
// after it.
const PhoneHardwareUnavailable = "this phone's secure hardware is not available to this app yet"

// UserMessage is the sentence an app can show a person as it is.
func (e *ErrRootSeedCannotLiveHere) UserMessage() string {
	if e.Phone {
		return PhoneHardwareUnavailable
	}
	return "this machine cannot protect an identity's root seed, so none was written"
}

// cannotLiveHere builds the refusal, marking it as a phone's where it is one.
func cannotLiveHere(cap Capability, reason string) *ErrRootSeedCannotLiveHere {
	return &ErrRootSeedCannotLiveHere{Capability: cap, Reason: reason, Phone: thisIsAPhone()}
}

// isDevBuild is the compiled build mode behind a seam so a test can stand a
// development build. It is not reachable from outside the package, and the mode
// itself is a link-time constant (package buildmode, ADR-043), never read from
// the environment or a setting.
var isDevBuild = buildmode.IsDev

// thisIsAPhone is whether this build is the Android core.
var thisIsAPhone = platformIsAPhone

// UseThisIsAPhone makes this process word its refusals as a phone's, for tests
// on a host that is not one. It returns a function that undoes it. It changes
// wording and the no-wrapper reason only; it opens no gate.
func UseThisIsAPhone() (restore func()) {
	prev := thisIsAPhone
	thisIsAPhone = func() bool { return true }
	return func() { thisIsAPhone = prev }
}

func (e *ErrRootSeedCannotLiveHere) Error() string {
	if e.Phone {
		msg := PhoneHardwareUnavailable + ", so no identity was created or restored on it and nothing was written: " + e.Reason
		if e.Capability.Status != "" {
			msg += " (" + e.Capability.String() + ")"
		}
		return msg + ". Update the app, or pair this phone to an identity kept elsewhere"
	}
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
//
// THE RULE IS "STORED ONLY UNDER A PROTECTION THIS PLATFORM ACTUALLY HAS". A
// production build needs proven-usable key protection AND a seed wrapper that
// works (the iOS Secure Enclave, the app's StrongBox/TEE key on Android, the
// sealed machine's volume). There is no phone exemption: an Android app that
// registers no wrapper is refused in production like any other machine that
// cannot wrap the seed (owner's decision, 2026-11-05).
//
// A development build is exempt, and says so wherever the state is shown
// (ReportSeedProtection): it may hold the seed, never presented as protected.
func rootSeedMayLiveHere(cap Capability, wrapperWorks, dev bool) bool {
	return dev || (cap.RootKeyPermitted() && wrapperWorks)
}

// checkPlacement is the founding rule: a root identity lives only where the
// machine can prove its software (a phone, a sealed machine). Having a Secure
// Enclave and a working wrapper is not enough, or a production Mac would hold
// a root identity it is not allowed to found.
func checkPlacement(dataDir string) error {
	if v := MayFoundAnIdentityHere(dataDir); !FoundingPermitted(v, isDevBuild()) {
		return cannotLiveHere(detectCapability(), v.Why)
	}
	return nil
}

// CheckRootSeedMayLiveHere asks whether a person's root seed may be written on
// this machine, without writing anything. Callers that have work to do before
// the write (recovery restores files first) ask this first so a refusal
// touches nothing.
func CheckRootSeedMayLiveHere(dataDir string) error {
	if err := checkPlacement(dataDir); err != nil {
		return err
	}
	cap := detectCapability()
	works := wrapperWorksAt(platformSeedWrapper(), dataDir)
	if rootSeedMayLiveHere(cap, works, isDevBuild()) {
		return nil
	}
	reason := "its key protection is not proven usable"
	if cap.RootKeyPermitted() {
		reason = "key hardware is usable but " + whyNotWrappedAt(dataDir)
	}
	return cannotLiveHere(cap, reason)
}

// StoreIdentityRootSeed persists a person's root seed. It refuses, having
// written nothing, where the machine cannot protect it; and outside a
// development build it cannot write the plaintext envelope at all.
func StoreIdentityRootSeed(dataDir string, seed []byte) error {
	if err := CheckRootSeedMayLiveHere(dataDir); err != nil {
		return err
	}
	// Production: a wrapper is mandatory, so the check inside storeSeed is a
	// second, independent lock on the same door.
	return storeSeedAs(dataDir, seed, platformSeedWrapper(), !isDevBuild(), holderIdentity)
}

// IsRootSeedRefusal reports whether err is the refusal above.
func IsRootSeedRefusal(err error) bool {
	var e *ErrRootSeedCannotLiveHere
	return errors.As(err, &e)
}
