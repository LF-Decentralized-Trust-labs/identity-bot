//go:build !linux && !windows && !android

package secureenclave

func newTPMSigner() PlatformSigner {
	return nil
}

func newStrongBoxSigner() PlatformSigner {
	return nil
}