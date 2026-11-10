//go:build darwin && !ios

package server

import "runtime"

// A Mac: whether the root seed is under the Secure Enclave is the seed
// wrapper's answer (macEnclaveStatus). An Apple-silicon CPU says only that the
// hardware is there.
func detectEnclave(wrap seedWrapFacts) EnclaveStatusResponse {
	return macEnclaveStatus(runtime.GOARCH == "arm64", wrap)
}
