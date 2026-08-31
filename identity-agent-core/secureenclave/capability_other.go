//go:build !(linux && !android) && !(darwin && cgo) && !windows

// Narrowed 2026-08-31. This used to catch darwin as well, so every Mac, iPhone
// and iPad answered "we have not looked" while the attestation signer on the
// very same build was creating and using Secure Enclave keys. capability_darwin.go
// now answers for them by asking the enclave for a key.
//
// Windows was excluded on the same day, by capability_windows.go.
//
// What still lands here: Android, iOS or macOS built without cgo, and anything
// unrecognised. Android is the one that matters — it is a phone, and a phone is
// one of only two places a root key may live.

package secureenclave

import "runtime"

// DetectCapability on a platform whose detector has not been written yet.
//
// It returns Unknown rather than Absent, and that distinction is the entire
// point of this package. Three platform signers here answer a hardcoded false,
// which downstream reads as "this machine has no security hardware" — untrue
// for most Windows machines, since Windows 11 cannot ship without a TPM, and
// untrue for most Android phones, which have had a TEE since Android 6.
//
// Saying "we have not looked" costs nothing and is true. Saying "there is
// nothing there" is a claim about somebody's hardware that we have not earned,
// and under GS-12 it would cap their score for a fact we never checked.
func DetectCapability() Capability {
	return NotImplemented(runtime.GOOS)
}

// SealedHostCapable reports whether this machine can launch sealed guests.
// Only Linux hosts can, so everywhere else the answer is a plain no rather
// than an unknown — there is no confidential-computing stack to have missed.
func SealedHostCapable() bool { return false }
