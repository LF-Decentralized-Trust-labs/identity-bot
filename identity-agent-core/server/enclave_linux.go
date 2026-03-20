//go:build linux

package server

import "os"

func detectEnclave() EnclaveStatusResponse {
	present := false
	enabled := false

	// /dev/tpm0 = TPM chip present
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		present = true
	}

	// /dev/tpmrm0 = TPM resource manager (kernel driver loaded, TPM accessible)
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		enabled = true
	}

	if present && enabled {
		return EnclaveStatusResponse{
			HardwareBacked: true,
			BackingType:    "tpm2",
			BackingLabel:   "Linux TPM 2.0",
			TpmPresent:     &present,
			TpmEnabled:     &enabled,
		}
	}

	if present && !enabled {
		return EnclaveStatusResponse{
			HardwareBacked: false,
			BackingType:    "libsecret",
			BackingLabel:   "Linux Secret Service (TPM present but not enabled)",
			TpmPresent:     &present,
			TpmEnabled:     &enabled,
		}
	}

	hardwareBacked := false
	return EnclaveStatusResponse{
		HardwareBacked: hardwareBacked,
		BackingType:    "libsecret",
		BackingLabel:   "Linux Secret Service (software)",
		TpmPresent:     &present,
		TpmEnabled:     &enabled,
	}
}
