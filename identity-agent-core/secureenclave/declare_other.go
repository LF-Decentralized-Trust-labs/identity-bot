//go:build !android

package secureenclave

// DeclareHardwareKeyProtection does nothing off Android, and that is the right
// behaviour rather than a stub.
//
// Every other platform's detector asks the operating system itself, so it is
// authoritative and an app's opinion must not be able to override it. Android
// is the exception because its Keystore cannot be reached from Go at all — see
// capability_android.go. The function exists here so mobilecore compiles for
// every target with one signature, and so an app that calls it unconditionally
// is correct everywhere rather than having to know which platform it is on.
func DeclareHardwareKeyProtection(status, kind, reason, detail string) {}
