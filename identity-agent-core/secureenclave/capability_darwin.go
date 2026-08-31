//go:build darwin && cgo

// What an Apple machine can protect a key with — established by asking the
// Secure Enclave to make one.
//
// Both platforms, deliberately. The tag is `darwin`, not `darwin && arm64` and
// not `ios`, so this is the detector for iPhones, iPads and Macs alike. They
// run the same Security framework and the same call decides it. An Intel Mac
// with a T2 has an enclave and answers yes; a 2015 MacBook has none and answers
// no; nothing in the build constraint has to know which, because the machine is
// asked rather than guessed at.
//
// WHY THIS CREATES A KEY. The contract in capability.go says Usable is proven,
// "a key was actually created in the hardware and discarded. Nothing short of
// doing the thing counts." Reading a model number or a CPU feature bit is the
// guess this package exists to stop. So the detector generates a real P-256 key
// on the enclave's token and throws it away.
//
// The key is EPHEMERAL — kSecAttrIsPermanent is false — so nothing is written
// to the keychain and nothing accumulates. That is not only tidiness: a
// detector that stored something would prompt for a keychain password, on every
// launch, before anybody had asked for anything. Its access control names
// private-key usage alone, with no biometry and no passcode, so the enclave
// will make it without asking the person in front of the machine.
//
// This is the same call the attestation signer already makes on the same build
// (signer_darwin_enclave.go), which is why the capability was known to be
// reachable here long before anything reported it.

package secureenclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

// se_probe asks the Secure Enclave for one ephemeral key and immediately drops
// it. Returns 0 when the enclave made it, and otherwise the OSStatus or CFError
// code, which the Go side maps to a status.
//
// A negative return distinguishes our own failures from the platform's: -1 is
// "the access control could not be built", which says nothing about hardware.
static int se_probe(void) {
    CFErrorRef acErr = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        NULL,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        &acErr);
    if (access == NULL) {
        if (acErr) CFRelease(acErr);
        return -1;
    }

    CFMutableDictionaryRef privateAttrs = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    // Ephemeral on purpose — see the note above.
    CFDictionarySetValue(privateAttrs, kSecAttrIsPermanent, kCFBooleanFalse);
    CFDictionarySetValue(privateAttrs, kSecAttrAccessControl, access);

    CFMutableDictionaryRef params = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, CFSTR("256"));
    CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(params, kSecPrivateKeyAttrs, privateAttrs);

    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(params, &err);

    int code = 0;
    if (key == NULL) {
        code = err ? (int)CFErrorGetCode(err) : -2;
        if (code == 0) code = -2;
    } else {
        CFRelease(key);
    }
    if (err) CFRelease(err);
    CFRelease(params);
    CFRelease(privateAttrs);
    CFRelease(access);
    return code;
}
*/
import "C"

import "strconv"

// DetectCapability asks this machine's Secure Enclave to make a key.
func DetectCapability() Capability {
	switch code := int(C.se_probe()); {
	case code == 0:
		return Capability{Status: Usable, Kind: KindAppleEnclave}

	// errSecUnimplemented. The enclave token is not implemented on this
	// hardware, which is the operating system telling us there is no Secure
	// Enclave here — a 2015 Mac, or a VM with no enclave passed through. This
	// is the one code positive enough to answer Absent, which capability.go
	// says may never be guessed at.
	case code == -4:
		return Capability{
			Status: Absent,
			Reason: "no_secure_enclave_on_this_hardware",
			Detail: "the Secure Enclave token is unimplemented on this machine (errSecUnimplemented)",
		}

	// Our own failure, one layer above the hardware. Says nothing about the
	// machine, so it must not be reported as though it did.
	case code == -1:
		return Unproven("access_control_unavailable",
			"the access control for an enclave key could not be constructed")

	// errSecInteractionNotAllowed (-25308): the keychain is locked, or this is
	// running somewhere with no session to prompt in — a daemon, or ssh. The
	// hardware is very likely there and cannot be reached right now, which is
	// exactly what Present means and exactly why it is not Absent.
	case code == -25308:
		return Capability{
			Status: Present,
			Kind:   KindAppleEnclave,
			Reason: "keychain_interaction_not_allowed",
			Detail: "the enclave could not be used without an interactive session (errSecInteractionNotAllowed)",
		}

	// errSecAuthFailed (-25293) and errSecUserCanceled (-128): something was
	// asked of the person and did not succeed. The enclave answered, so it is
	// there.
	case code == -25293 || code == -128:
		return Capability{
			Status: Present,
			Kind:   KindAppleEnclave,
			Reason: "enclave_authorisation_failed",
			Detail: "the enclave refused to create a key without authorisation (" +
				strconv.Itoa(code) + ")",
		}

	// Everything else. The first release's job is to find out which codes real
	// machines produce, so the code is carried rather than discarded — and the
	// answer stays Unknown, because an unrecognised failure is not evidence of
	// absent hardware.
	default:
		return Unproven("enclave_probe_failed",
			"creating a key in the Secure Enclave failed with code "+strconv.Itoa(code))
	}
}

// SealedHostCapable reports whether this machine can launch sealed guests.
// No Apple platform can, so this is a plain no rather than an unknown — there
// is no confidential-computing stack here to have missed.
func SealedHostCapable() bool { return false }
