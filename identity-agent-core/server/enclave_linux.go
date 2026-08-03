//go:build linux

package server

import (
	"os"

	"identity-agent-core/secureenclave"
)

// detectEnclave reports what is actually protecting keys on this host.
//
// A TPM device node tells you a chip is installed and the kernel driver is
// loaded. It does not tell you that anything is protected by it — those are
// different questions, and this function used to answer the second by checking
// the first. On Linux no seed wrapper exists yet, so the root seed is stored
// unwrapped while /dev/tpm0 is present on most server hardware, and the status
// endpoint asserted hardware_backed on every one of them.
//
// That direction of error is the dangerous one. An absent security indicator
// prompts someone to go and check; a false one is relied upon. So the claim is
// now made by the code that would do the wrapping, and the TPM fields still
// report the hardware honestly — present, enabled, and not yet used.
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

	if secureenclave.SeedWrapAvailable() {
		return EnclaveStatusResponse{
			HardwareBacked: true,
			BackingType:    secureenclave.SeedWrapScheme(),
			BackingLabel:   "Linux TPM 2.0",
			TpmPresent:     &present,
			TpmEnabled:     &enabled,
		}
	}

	// No wrapper. Say so, and say why — the distinction between "you have no
	// TPM" and "you have one we do not use yet" is the difference between
	// buying hardware and waiting for us.
	label := "Linux Secret Service (software)"
	switch {
	case present && enabled:
		label = "software — a TPM 2.0 is present and enabled, but no key is wrapped by it yet"
	case present:
		label = "software — a TPM 2.0 is present but not enabled"
	}

	return EnclaveStatusResponse{
		HardwareBacked: false,
		BackingType:    "libsecret",
		BackingLabel:   label,
		TpmPresent:     &present,
		TpmEnabled:     &enabled,
	}
}
