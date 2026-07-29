//go:build darwin && (!cgo || !arm64)

package secureenclave

func newDarwinSecureEnclaveSigner() PlatformSigner {
	return nil
}
