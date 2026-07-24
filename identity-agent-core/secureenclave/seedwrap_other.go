//go:build !(darwin && cgo && arm64)

package secureenclave

// No hardware seed wrapper on this platform yet (TPM on Windows/Linux, StrongBox
// on Android, and TEE-backed hosts slot in behind the same SeedWrapper seam).
// The seed is stored in the envelope unwrapped, exactly as protected as before
// this layer existed.
func newPlatformSeedWrapper() SeedWrapper { return nil }
