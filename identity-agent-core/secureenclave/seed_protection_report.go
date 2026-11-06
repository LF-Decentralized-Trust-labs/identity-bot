package secureenclave

import "os"

// What the apps are told about the seed's protection.
//
// A seed that is not under StrongBox/TEE/Secure Enclave must never be presented
// as protected, anywhere the state is shown. Production refuses to hold such a
// seed at all (CheckRootSeedMayLiveHere), so in production this report can show
// "not protected" for exactly one thing: an identity that was stored unwrapped
// before that rule and is still readable (see LoadRootSeed). A development build
// may hold one on purpose, and says so here.

// SeedProtectionState is the answer, in plain terms.
type SeedProtectionState struct {
	// Stored is whether a root seed is on disk.
	Stored bool `json:"stored"`
	// Protection is what the stored seed's envelope records: "hardware-wrapped",
	// "sealed-volume" or "unwrapped". Empty when no seed is stored.
	Protection string `json:"protection,omitempty"`
	// HardwareProtected is true only when the seed that is (or would be) stored
	// is under hardware: the stored envelope says so, or none is stored yet and
	// the wrapper works here.
	HardwareProtected bool `json:"hardwareProtected"`
	// NotProtectedWhy is non-empty exactly when HardwareProtected is false: the
	// reason, in words an app can show.
	NotProtectedWhy string `json:"notProtectedWhy,omitempty"`
	// HowItGetsProtected says how an unprotected stored seed becomes protected.
	HowItGetsProtected string `json:"howItGetsProtected,omitempty"`
	// DevelopmentBuild is true for a development build, the only kind that may
	// found an identity on a seed that is not hardware-protected.
	DevelopmentBuild bool `json:"developmentBuild"`
}

// HowAnUnprotectedSeedGetsProtected is told to the app beside an unprotected
// stored seed.
const HowAnUnprotectedSeedGetsProtected = "the seed is still readable and still works; once the app " +
	"supplies its StrongBox/TEE key the core wraps it automatically the next time it opens the seed, " +
	"and this state then reads hardware-wrapped"

// ReportSeedProtection says what protects the root seed in dataDir, or what
// would. It reads the envelope only and never opens the seed.
func ReportSeedProtection(dataDir string) SeedProtectionState {
	st := SeedProtectionState{DevelopmentBuild: isDevBuild()}
	p, _, why, err := RootSeedProtection(dataDir)
	if err == nil {
		st.Stored = true
		st.Protection = p
		st.HardwareProtected = p != ProtectionUnwrapped
		if !st.HardwareProtected {
			st.NotProtectedWhy = why
			if st.NotProtectedWhy == "" {
				st.NotProtectedWhy = whyNotWrappedAt(dataDir)
			}
			st.HowItGetsProtected = HowAnUnprotectedSeedGetsProtected
		}
		return st
	}
	if !os.IsNotExist(err) {
		// A seed file we cannot read: say nothing is claimed about it.
		st.Stored = true
		st.NotProtectedWhy = "the stored seed could not be read: " + err.Error()
		return st
	}
	st.HardwareProtected = wrapperWorksAt(platformSeedWrapper(), dataDir)
	if !st.HardwareProtected {
		st.NotProtectedWhy = whyNotWrappedAt(dataDir)
	}
	return st
}

// RootKeyPermittedHere is RootKeyPermitted for the question apps actually ask:
// may this machine hold a root key, given that the seed must go under hardware?
// In production that is the hardware's answer AND a working wrapper; refusal
// says why, in the phone's words on a phone.
func RootKeyPermittedHere(dataDir string) (permitted bool, refusal string) {
	cap := detectCapability()
	if !cap.RootKeyPermitted() {
		return false, ""
	}
	if isDevBuild() || wrapperWorksAt(platformSeedWrapper(), dataDir) {
		return true, ""
	}
	if thisIsAPhone() {
		return false, PhoneHardwareUnavailable
	}
	return false, "key hardware is usable but " + whyNotWrappedAt(dataDir)
}
