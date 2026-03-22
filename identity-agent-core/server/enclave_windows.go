//go:build windows

package server

import (
	"golang.org/x/sys/windows/registry"
)

func detectEnclave() EnclaveStatusResponse {
	present := false
	enabled := false

	// TPM 2.0 present: HKLM\HARDWARE\DEVICEMAP\TPM exists
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DEVICEMAP\TPM`, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		present = true
	}

	// TPM enabled: HKLM\SYSTEM\CurrentControlSet\Services\TPM Start value != 4 (4 = disabled)
	if present {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\TPM`, registry.QUERY_VALUE)
		if err == nil {
			defer sk.Close()
			startVal, _, err := sk.GetIntegerValue("Start")
			if err == nil && startVal != 4 {
				enabled = true
			}
		}
	}

	if present && enabled {
		return EnclaveStatusResponse{
			HardwareBacked: true,
			BackingType:    "tpm2",
			BackingLabel:   "Windows TPM 2.0",
			TpmPresent:     &present,
			TpmEnabled:     &enabled,
		}
	}

	// TPM present but not enabled by OS
	if present && !enabled {
		return EnclaveStatusResponse{
			HardwareBacked: false,
			BackingType:    "dpapi",
			BackingLabel:   "Windows DPAPI (TPM present but not enabled)",
			TpmPresent:     &present,
			TpmEnabled:     &enabled,
		}
	}

	// No TPM — fall back to DPAPI (software-backed)
	hardwareBacked := false
	return EnclaveStatusResponse{
		HardwareBacked: hardwareBacked,
		BackingType:    "dpapi",
		BackingLabel:   "Windows DPAPI (software)",
		TpmPresent:     &present,
		TpmEnabled:     &enabled,
	}
}
