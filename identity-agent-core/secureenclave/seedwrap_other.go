//go:build !(ios && cgo && arm64) && !(darwin && cgo && sepblob && !ios) && !windows && !android && !(linux && !android)

package secureenclave

// No hardware seed wrapper is compiled in for this build, and nothing pretends
// otherwise: the platform wrapper is nil, SeedWrapAvailable is false and the
// envelope says "none". Every platform the product supports has a wrapper behind
// the SeedWrapper seam in its own file; what reaches here is a build that left
// one out, such as a macOS core built without cgo or without the sepblob tag.
func newPlatformSeedWrapper() SeedWrapper { return nil }
