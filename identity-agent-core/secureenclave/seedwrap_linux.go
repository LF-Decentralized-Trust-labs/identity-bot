//go:build linux && !android

package secureenclave

// Linux has no hardware key wrapper yet (TPM seals slot in behind SeedWrapper),
// but a sealed machine — the black box — protects its seed with the sealed
// volume, and says so (seedwrap_sealed.go). Elsewhere on Linux the wrapper is
// present and reports itself unavailable, so a desktop stores unwrapped exactly
// as before and a production desktop still refuses to hold a root identity.
func newPlatformSeedWrapper() SeedWrapper { return sealedVolumeWrapper{} }
