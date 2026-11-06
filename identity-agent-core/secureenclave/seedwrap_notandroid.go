//go:build !android

package secureenclave

// platformIsAPhone: only the Android core is a phone (iOS has its own wrapper
// and never reaches the no-wrapper case).
func platformIsAPhone() bool { return false }
