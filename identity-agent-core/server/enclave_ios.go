//go:build ios

package server

// iOS: every device capable of running this app has a Secure Enclave (all
// iPhones/iPads since the iPhone 5s / A7), and the root seed is wrapped by a
// key in it; the report is whether that wrapper works (iosEnclaveStatus).
// GOOS=ios also satisfies the `darwin` build tag, so without this file the
// macOS detection would run instead.
func detectEnclave(wrap seedWrapFacts) EnclaveStatusResponse {
	return iosEnclaveStatus(wrap)
}
