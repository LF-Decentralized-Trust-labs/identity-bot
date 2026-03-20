//go:build darwin

package server

import "runtime"

func detectEnclave() EnclaveStatusResponse {
	if runtime.GOARCH == "arm64" {
		// Apple Silicon — Secure Enclave is always present and always active
		return EnclaveStatusResponse{
			HardwareBacked: true,
			BackingType:    "secure_enclave",
			BackingLabel:   "Apple Secure Enclave",
		}
	}

	// Intel Mac — Keychain uses software AES encryption (no dedicated secure enclave)
	return EnclaveStatusResponse{
		HardwareBacked: false,
		BackingType:    "keychain_software",
		BackingLabel:   "macOS Keychain (software)",
	}
}
