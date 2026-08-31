//go:build windows

// What a Windows machine can protect a key with — established by asking the
// TPM to make one.
//
// This is the platform capability.go singles out by name, and the warning is
// worth repeating because it is the whole reason this file is careful:
//
//	"Three of the five platform signers here have an Available() that returns a
//	hardcoded false — not detection that found nothing, but detection nobody
//	wrote. On Windows that would be wrong for essentially every machine, since
//	Windows 11 cannot ship without a TPM."
//
// And the trap immediately next to it, quoted there from Google's own
// go-attestation: *"If we fail to initialize the Platform Crypto Provider, we
// assume a TPM is not present."* That single line turns a failure to open a
// provider into a claim about somebody's hardware. This file must not do it,
// which is why a failure to open the provider is Unknown here and never Absent.
//
// TWO QUESTIONS, ASKED SEPARATELY. Whether a TPM exists is answered by the TBS
// interface, which is the operating system's own register of the device.
// Whether we can USE it is answered by creating a key. Collapsing them is how
// a locked-out or unprovisioned TPM comes to be reported as no TPM at all —
// the same defect capability_linux.go was written to avoid, where a single
// open() made EACCES indistinguishable from ENOENT.
//
// No cgo. The calls go through golang.org/x/sys/windows, so this builds with
// CGO_ENABLED=0 like the rest of the Windows target.

package secureenclave

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ncrypt = windows.NewLazySystemDLL("ncrypt.dll")
	tbs    = windows.NewLazySystemDLL("tbs.dll")

	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")

	procTbsiGetDeviceInfo = tbs.NewProc("Tbsi_GetDeviceInfo")
)

// The TPM-backed CNG provider. Keys created here live in the TPM; the handle is
// all that ever reaches this process.
const msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"

// tbsErrTPMNotFound is TBS_E_TPM_NOT_FOUND. It is the operating system stating
// that this machine has no TPM, which is the positive evidence capability.go
// requires before anything may be called Absent.
const tbsErrTPMNotFound = 0x8028400F

// tpmDeviceInfo mirrors TPM_DEVICE_INFO. Only the version fields are read; the
// struct has to match in size and order regardless.
type tpmDeviceInfo struct {
	StructVersion    uint32
	TPMVersion       uint32
	TPMInterfaceType uint32
	TPMImpRevision   uint32
}

// aTPMExists asks the operating system's own device register whether this
// machine has a TPM, without trying to use it.
//
// Returns (exists, established). When established is false nothing was learned,
// which is different from learning that there is none — and keeping them apart
// is the entire point of this file.
func aTPMExists() (bool, bool) {
	if err := procTbsiGetDeviceInfo.Find(); err != nil {
		return false, false
	}
	var info tpmDeviceInfo
	r, _, _ := procTbsiGetDeviceInfo.Call(
		uintptr(unsafe.Sizeof(info)),
		uintptr(unsafe.Pointer(&info)),
	)
	switch uint32(r) {
	case 0:
		return true, true
	case tbsErrTPMNotFound:
		return false, true
	default:
		// Access denied, service stopped, an unrecognised code. We did not
		// learn whether a TPM is there.
		return false, false
	}
}

// DetectCapability asks this machine's TPM to make a key.
//
// The key is EPHEMERAL — NCryptCreatePersistedKey with no name — so nothing is
// stored, nothing accumulates in the TPM's limited persistent storage, and
// nothing has to be cleaned up if this process dies mid-probe.
func DetectCapability() Capability {
	if err := ncrypt.Load(); err != nil {
		return Unproven("ncrypt_unavailable",
			"ncrypt.dll could not be loaded: "+err.Error())
	}

	var provider windows.Handle
	name, err := windows.UTF16PtrFromString(msPlatformCryptoProvider)
	if err != nil {
		return Unproven("provider_name_unusable", err.Error())
	}
	if r, _, _ := procOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(name)),
		0,
	); r != 0 {
		// THE go-attestation TRAP. A provider that would not open is not a
		// machine without a TPM, so ask the register before saying anything
		// about this person's hardware.
		if exists, established := aTPMExists(); established && !exists {
			return Capability{
				Status: Absent,
				Reason: "no_tpm_on_this_machine",
				Detail: "the platform crypto provider would not open and the OS reports no TPM device (TBS_E_TPM_NOT_FOUND)",
			}
		} else if established && exists {
			return Capability{
				Status: Present,
				Kind:   KindTPM2,
				Reason: "platform_crypto_provider_unavailable",
				Detail: fmt.Sprintf("a TPM is present but its CNG provider would not open (0x%X) — "+
					"it may need to be provisioned, cleared, or its service started", uint32(r)),
			}
		}
		return Unproven("platform_crypto_provider_unavailable",
			fmt.Sprintf("the platform crypto provider would not open (0x%X) and whether a TPM "+
				"exists could not be established", uint32(r)))
	}
	defer procFreeObject.Call(uintptr(provider))

	// EC first, RSA second, and the second one matters.
	//
	// Asking only for ECDSA_P256 understates any TPM that does not do elliptic
	// curves. A TPM 1.2 module is RSA-only by specification, and some early
	// 2.0 modules shipped without the NIST P-256 algorithm — those machines
	// protect an RSA key perfectly well, and reporting them as merely Present
	// would refuse a root key on hardware that can hold one.
	//
	// The order is deliberate: EC is what everything else here uses, so a TPM
	// that can do it should be recorded as doing it.
	var lastCode uint32
	for _, algorithm := range []string{"ECDSA_P256", "RSA"} {
		code, ok := tryOneKey(provider, algorithm)
		if ok {
			return Capability{Status: Usable, Kind: KindTPM2}
		}
		lastCode = code
	}

	// The provider opened and neither key would be made. That is the ordinary
	// shape of an unprovisioned or locked-out TPM, so the answer is Present —
	// and never Absent, because the provider opening already proved something
	// is there.
	return tpmIsThereButRefused("no_key_algorithm_accepted", lastCode)
}

// tryOneKey asks the TPM for one ephemeral key of the named algorithm.
//
// The key is unnamed, so nothing is written to the TPM's small persistent
// storage and nothing has to be cleaned up if this process dies mid-probe.
func tryOneKey(provider windows.Handle, algorithm string) (uint32, bool) {
	name, err := windows.UTF16PtrFromString(algorithm)
	if err != nil {
		return 0, false
	}
	var key windows.Handle
	if r, _, _ := procCreatePersistedKey.Call(
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)),
		0, // no key name — ephemeral, so nothing is stored
		0,
		0,
	); r != 0 {
		return uint32(r), false
	}
	defer procFreeObject.Call(uintptr(key))

	// Finalizing is where the TPM actually generates it. Creating the handle
	// proves only that the provider accepted the request.
	if r, _, _ := procFinalizeKey.Call(uintptr(key), 0); r != 0 {
		return uint32(r), false
	}
	return 0, true
}

// tpmIsThereButRefused describes a TPM that answered and would not do the work,
// for any key algorithm it was offered. Never Absent: the provider opened, so
// the hardware is there.
func tpmIsThereButRefused(reason string, code uint32) Capability {
	return Capability{
		Status: Present,
		Kind:   KindTPM2,
		Reason: reason,
		Detail: fmt.Sprintf("the TPM's provider opened but creating a key failed (0x%X) — "+
			"the TPM may be unprovisioned, in lockout, or out of storage", code),
	}
}

// SealedHostCapable reports whether this machine can launch sealed guests.
//
// A Windows host cannot, whatever its CPU: the sealed-guest stack we use is
// Linux + KVM. This is a plain no rather than an unknown, in the same way
// capability_darwin.go answers no — there is no confidential-computing path
// here to have missed.
func SealedHostCapable() bool { return false }
