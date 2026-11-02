//go:build !android

package secureenclave

// Only a phone is allowed to hold a root identity's seed unwrapped (in
// production); see seedwrap_android.go.
func platformUnwrappedReason() string { return "" }
