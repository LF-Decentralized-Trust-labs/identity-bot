//go:build windows

package server

import (
	"golang.org/x/sys/windows/registry"
)

// detectEnclave reads the TPM from the registry and reports it as found; whether
// the root seed is under it is the seed wrapper's answer (windowsEnclaveStatus).
// A TPM in the registry is not a key the TPM will open.
func detectEnclave(wrap seedWrapFacts) EnclaveStatusResponse {
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

	return windowsEnclaveStatus(present, enabled, wrap)
}
