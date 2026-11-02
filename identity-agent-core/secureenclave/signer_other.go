//go:build !darwin && !linux && !windows && !android

package secureenclave

// No Apple Secure Enclave on this operating system. The other platforms each
// declare this beside their own signer; this is the same answer for every
// operating system none of them cover, so the package builds there too.
func newDarwinSecureEnclaveSigner(dataDir string) PlatformSigner { return nil }
