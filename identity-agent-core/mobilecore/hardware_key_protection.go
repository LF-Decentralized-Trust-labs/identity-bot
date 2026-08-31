package mobilecore

import "identity-agent-core/secureenclave"

// Reporting what protects a key on this phone.
//
// On every other platform the core asks the operating system itself: macOS goes
// to the Security framework, Windows to the platform crypto provider, Linux to
// the device nodes. Android's Keystore is a Java API with no path to it from
// Go, so the app probes it and reports the result here. The core still owns
// what the answer MEANS — which statuses exist, and that only a proven one may
// hold a root key — and the app supplies only what it observed.
//
// [status] is one of "usable", "present_unusable", "absent" or "unknown", and
// they carry the meanings capability.go defines. In particular:
//
//   - "usable" is PROVEN, never inferred. A key must actually have been
//     generated in the Keystore and thrown away. Reading a feature flag, an API
//     level, or a device model is the guess this whole mechanism exists to stop.
//   - "absent" needs positive evidence that there is no hardware-backed
//     Keystore. An exception nobody recognised is "unknown", not "absent" —
//     telling somebody their phone has no security hardware when the truth is
//     that a call failed is a false statement about their property.
//
// [kind] should be "android_strongbox" when the key went to StrongBox and
// "android_tee" when it went to the trusted execution environment. The
// distinction is worth carrying: they are different hardware with different
// guarantees, and a phone that has only the TEE is still a phone that can hold
// a root key.
//
// [reason] is a short stable slug for support and for anything that has to
// explain a refusal. [detail] carries the raw platform exception, including its
// message — the first release's job is to find out what real phones actually
// say, and a message that was discarded is one nothing can learn from.
//
// Must be called before StartServer, like DeclareEntityType. An app that stays
// quiet gets "unknown", which is the honest answer for nobody having looked and
// is never rendered as a claim about the phone.
func DeclareHardwareKeyProtection(status, kind, reason, detail string) {
	secureenclave.DeclareHardwareKeyProtection(status, kind, reason, detail)
}
