//go:build android

package server

// Android: the phone's secure hardware is reached through the app's Keystore
// key, which the core verifies by its attestation and wraps the root seed to
// (secureenclave/seedwrap_host.go). So the report comes from that wrapper and
// names the level its attestation proved, StrongBox or the TEE.
//
// GOOS=android also satisfies the `linux` build tag, so without this file the
// Linux detection would run and describe the phone as a TPM host.
func detectEnclave(wrap seedWrapFacts) EnclaveStatusResponse {
	return androidEnclaveStatus(wrap)
}
