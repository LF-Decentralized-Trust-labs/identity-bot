//go:build darwin && !cgo

// The counterpart to signer_darwin_enclave.go, which now covers every Mac when
// cgo is on. This is the no-cgo build only — which is, today, how the macOS
// backend actually ships, so this is the file that runs in production.

package secureenclave

func newDarwinSecureEnclaveSigner(dataDir string) PlatformSigner {
	return nil
}
