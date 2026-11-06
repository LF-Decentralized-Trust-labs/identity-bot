//go:build android

package secureenclave

// Android's seed is wrapped by the app's Keystore key (StrongBox where the phone
// has one, the TEE otherwise), driven through SeedWrapHost because the Keystore
// cannot be reached from Go. See seedwrap_host.go for what the core insists on.
func newPlatformSeedWrapper() SeedWrapper { return declaredHostSeedWrapper() }

// platformIsAPhone: an app that registers no wrapper is refused in a production
// build (noSeedWrapHostWhy); there is no old-app exemption.
func platformIsAPhone() bool { return true }
