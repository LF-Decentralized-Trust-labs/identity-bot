package secureenclave

import (
	"errors"
	"fmt"
	"runtime"
)

// THE CONTROLLER KEY OF A DESKTOP, UNDER THE GATE (ADR-074 section 3).
//
// A Mac or Windows PC never holds a root. What it holds is the key it signs with
// as a controller for its person's root device, and that is what a log-out must
// make unusable:
//
//	macOS    the Secure Enclave key blob the core holds itself is sealed under GK,
//	         so a locked profile's blob on disk is ciphertext
//	Windows  the TPM key's authorization value is HKDF(GK, "tpm-auth"), so the TPM
//	         itself refuses to sign without it and applies its own lockout
//
// This file is the part of that which does not depend on the operating system:
// which key a profile uses, the seal and the open of a blob under the gate, and
// the authorization value. The macOS signer (signer_darwin_sep.go) and the
// Windows signer (signer_windows.go) call it, so it is tested here once.

// GateKeyDeriver is what a GateSealer also implements when it can derive a key
// from GK for a purpose, without GK leaving it. info names the purpose, so two
// purposes never get one key.
type GateKeyDeriver interface {
	DeriveKey(info string, n int) ([]byte, error)
}

// tpmAuthInfo is the purpose of the key the TPM is given as the controller key's
// authorization value (ADR-074: HKDF(GK, "tpm-auth")).
const tpmAuthInfo = "tpm-auth"

// tpmAuthLen is the bytes derived: the provider turns the string into the TPM's
// 20-byte authorization, and 32 bytes of key are more than that can carry.
const tpmAuthLen = 32

// controllerKeyNameFor is the name of the controller key inside a platform that
// names keys: the profile's own when the profile at dataDir has a gate, base
// (the device-wide name) when it has none.
func controllerKeyNameFor(base, dataDir string) string {
	if id := profileOf(dataDir); id != "" {
		return ProfileKeyName(base, id)
	}
	return base
}

// sealForTheGate is blob as it is to be written for the profile at dataDir: under
// the gate key when the profile has one, which is what the returned scheme says,
// and untouched when it has none. A locked profile gets ErrIdentityLocked and
// nothing is sealed.
func sealForTheGate(dataDir string, blob []byte) (sealed []byte, scheme string, err error) {
	sealer, gated, err := theGateForThisSeedToStore(dataDir)
	if err != nil {
		return nil, "", err
	}
	if !gated {
		return blob, "", nil
	}
	sealed, err = sealer.Seal(blob)
	if err != nil {
		return nil, "", fmt.Errorf("seal the controller key under the gate key: %w", err)
	}
	return sealed, gateScheme, nil
}

// openFromTheGate reverses sealForTheGate for what was stored with scheme.
// needsGate is true when the profile has a gate and the blob was written before
// it had the layer: it is served, and the caller seals it again. A locked
// profile gets ErrIdentityLocked whatever is on disk, a blob sealed under a gate
// the profile no longer has is locked too, and a scheme this build does not know
// is refused.
func openFromTheGate(dataDir string, stored []byte, scheme string) (blob []byte, needsGate bool, err error) {
	sealer, gated, err := theGateForThisSeed(dataDir)
	if err != nil {
		return nil, false, err
	}
	switch {
	case scheme == "" && !gated:
		return stored, false, nil
	case scheme == "":
		return stored, true, nil
	case scheme != gateScheme:
		return nil, false, fmt.Errorf("the controller key is sealed under gate scheme %q, which this build cannot open", scheme)
	case sealer == nil:
		return nil, false, ErrIdentityLocked
	}
	blob, err = sealer.Open(stored)
	if err != nil {
		return nil, false, fmt.Errorf("the controller key does not open under the gate key: %w", err)
	}
	return blob, false, nil
}

// tpmAuthorizationFor is the TPM authorization value of the controller key of
// the profile at dataDir: HKDF(GK, "tpm-auth") when it has a gate, nil when it
// has none (the key then has no authorization value, as every machine key did).
// A locked profile has no GK and gets ErrIdentityLocked, so the TPM is never
// asked. A gate that cannot derive refuses rather than falling back to none: a
// controller key that silently has no authorization value is the failure.
func tpmAuthorizationFor(dataDir string) ([]byte, error) {
	sealer, gated, err := theGateForThisSeed(dataDir)
	if err != nil {
		return nil, err
	}
	if !gated {
		return nil, nil
	}
	d, ok := sealer.(GateKeyDeriver)
	if !ok {
		return nil, errors.New("this gate cannot derive the controller key's authorization value")
	}
	return d.DeriveKey(tpmAuthInfo, tpmAuthLen)
}

// tpmUsageAuthWide is the authorization value as the wide string the Platform
// Crypto Provider is given (NCRYPT_PIN_PROPERTY): the value written in hex, so no
// byte of it is one a string API would end on, then the terminator. The core
// hands the provider this same string when the key is made and when it is used,
// and the provider derives what the TPM keeps; the core computes no digest of its
// own. The caller zeroes the result.
func tpmUsageAuthWide(auth []byte) []uint16 {
	const hexdigits = "0123456789abcdef"
	w := make([]uint16, 0, 2*len(auth)+1)
	for _, c := range auth {
		w = append(w, uint16(hexdigits[c>>4]), uint16(hexdigits[c&15]))
	}
	return append(w, 0)
}

// controllerKeyIsHardwareHere names the hardware signer this build has for the
// platform, for the one answer a locked profile gives: its key exists and cannot
// be used. Empty where the build has no hardware controller key to lock.
var controllerKeyIsHardwareHere = func() (platform, label string) {
	switch runtime.GOOS {
	case "darwin":
		return "secure_enclave", "Apple Secure Enclave"
	case "windows":
		return "tpm2", "TPM 2.0 (Platform Crypto Provider)"
	}
	return "", ""
}

// lockedControllerKey is the signer a locked profile gets: one that exists, says
// what holds the key, and signs nothing. It is returned instead of falling
// through to the software signer, which would be a different key in a plain file.
type lockedControllerKey struct{ platform, label string }

func (s lockedControllerKey) Available() bool             { return true }
func (s lockedControllerKey) Platform() string            { return s.platform }
func (s lockedControllerKey) Label() string               { return s.label }
func (s lockedControllerKey) PublicKey() ([]byte, error)  { return nil, ErrIdentityLocked }
func (s lockedControllerKey) Sign([]byte) ([]byte, error) { return nil, ErrIdentityLocked }
