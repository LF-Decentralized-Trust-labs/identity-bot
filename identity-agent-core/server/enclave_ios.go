//go:build ios

package server

// iOS: every device capable of running this app has a Secure Enclave (all
// iPhones/iPads since the iPhone 5s / A7). Report the platform truth directly —
// GOOS=ios also satisfies the `darwin` build tag, so without this file the
// macOS detection (written for Apple Silicon vs Intel Macs) would run instead.
func detectEnclave() EnclaveStatusResponse {
	return EnclaveStatusResponse{
		HardwareBacked: true,
		BackingType:    "secure_enclave",
		BackingLabel:   "Apple Secure Enclave",
	}
}
