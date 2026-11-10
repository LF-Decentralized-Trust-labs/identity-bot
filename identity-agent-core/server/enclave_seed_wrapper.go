package server

import "identity-agent-core/secureenclave"

// What the security enclave report says, decided in an untagged file so every
// platform's answer is tested on every host. The per-platform detectEnclave
// files gather their hardware facts and call these; an android- or
// windows-tagged test could only run on that platform.
//
// THE RULE: hardwareBacked is whether the root seed is under hardware, which is
// what the seed wrapper answers. Not whether a chip is installed (a TPM in the
// registry, an Apple-silicon CPU), and not which attestation signer this build
// happens to use: those were guesses, and each one reported hardware
// protection somewhere it was not in force, or denied it somewhere it was. The
// hardware facts are still reported, beside it: the TPM fields, and
// keyProtection's status and kind. Why the seed is not under hardware is
// keyProtection.seedProtection.notProtectedWhy.

// seedWrapFacts is what the seed wrapper says about itself, from one check of
// it (secureenclave.SeedWrapNow).
type seedWrapFacts struct {
	// Wrapped is whether the root seed can be put under hardware right now.
	Wrapped bool
	// Scheme names what wraps it, "none" when nothing does.
	Scheme string
}

func readSeedWrap() seedWrapFacts {
	ok, scheme := secureenclave.SeedWrapNow()
	return seedWrapFacts{Wrapped: ok, Scheme: scheme}
}

// androidEnclaveStatus is what an Android phone reports.
//
// The phone's secure hardware is reached through the app's Keystore key, which
// the core checks by its attestation and then wraps the root seed to. The label
// names the level the attestation proved (StrongBox or the TEE), never one the
// app declared. There is no TPM on a phone, so the TPM fields are left out.
func androidEnclaveStatus(f seedWrapFacts) EnclaveStatusResponse {
	if !f.Wrapped {
		return EnclaveStatusResponse{
			HardwareBacked: false,
			BackingType:    f.Scheme,
			BackingLabel:   "Android Keystore (not protecting the root seed)",
		}
	}
	label := "Android Keystore"
	switch secureenclave.AndroidKeystoreLevel(f.Scheme) {
	case "strongbox":
		label = "Android StrongBox"
	case "tee":
		label = "Android TEE"
	}
	return EnclaveStatusResponse{
		HardwareBacked: true,
		BackingType:    f.Scheme,
		BackingLabel:   label,
	}
}

// iosEnclaveStatus is what an iPhone or iPad reports. Every device that runs
// the app has a Secure Enclave; whether the root seed is under it is the
// wrapper's answer, the same as everywhere else.
func iosEnclaveStatus(f seedWrapFacts) EnclaveStatusResponse {
	if !f.Wrapped {
		return EnclaveStatusResponse{
			HardwareBacked: false,
			BackingType:    f.Scheme,
			BackingLabel:   "software — the Secure Enclave is not protecting the root seed",
		}
	}
	return EnclaveStatusResponse{
		HardwareBacked: true,
		BackingType:    "secure_enclave",
		BackingLabel:   "Apple Secure Enclave",
	}
}

// macEnclaveStatus is what a Mac reports. appleSilicon says only that the CPU
// has a Secure Enclave, which is not the same as the root seed being under it
// (a build without the Secure Enclave seed wrapper, or a wrapper whose key
// fails, leaves it in the clear).
func macEnclaveStatus(appleSilicon bool, f seedWrapFacts) EnclaveStatusResponse {
	if f.Wrapped {
		return EnclaveStatusResponse{
			HardwareBacked: true,
			BackingType:    "secure_enclave",
			BackingLabel:   "Apple Secure Enclave",
		}
	}
	label := "macOS Keychain (software)"
	if appleSilicon {
		label = "software — this Mac has a Secure Enclave, but the root seed is not wrapped by it"
	}
	return EnclaveStatusResponse{
		HardwareBacked: false,
		BackingType:    "keychain_software",
		BackingLabel:   label,
	}
}

// windowsEnclaveStatus is what a Windows PC reports. present and enabled are
// what the registry says about the TPM, reported as they are; whether the root
// seed is under the TPM is the wrapper's answer, which actually opens the key.
func windowsEnclaveStatus(present, enabled bool, f seedWrapFacts) EnclaveStatusResponse {
	if f.Wrapped {
		return EnclaveStatusResponse{
			HardwareBacked: true,
			BackingType:    "tpm2",
			BackingLabel:   "Windows TPM 2.0",
			TpmPresent:     &present,
			TpmEnabled:     &enabled,
		}
	}
	label := "Windows DPAPI (software)"
	switch {
	case present && enabled:
		label = "software — a TPM 2.0 is present and enabled, but the root seed is not wrapped by it"
	case present:
		label = "Windows DPAPI (TPM present but not enabled)"
	}
	return EnclaveStatusResponse{
		HardwareBacked: false,
		BackingType:    "dpapi",
		BackingLabel:   label,
		TpmPresent:     &present,
		TpmEnabled:     &enabled,
	}
}
