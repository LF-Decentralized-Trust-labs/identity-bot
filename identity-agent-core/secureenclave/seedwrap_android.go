//go:build android

package secureenclave

// Android's seed is wrapped by the app's Keystore key (StrongBox where the phone
// has one, the TEE otherwise), driven through SeedWrapHost because the Keystore
// cannot be reached from Go. See seedwrap_host.go for what the core insists on.
func newPlatformSeedWrapper() SeedWrapper { return declaredHostSeedWrapper() }

// platformUnwrappedReason is non-empty only for an app that registered no
// wrapper at all.
func platformUnwrappedReason() string { return phoneUnwrappedReason(declaredSeedWrapHost() != nil) }
