//go:build windows

package secureenclave

// The Windows seed wrapper: an RSA-2048 key in the TPM, reached through the
// Microsoft Platform Crypto Provider.
//
// The machine's SIGNING key is P-256 (signer_windows.go) because a signature is
// all it does. A key that wraps a seed has to decrypt, and a TPM decrypts with
// RSA: the provider offers no ECDH, so there is no P-256 route to "the seed
// opens only here". RSA-OAEP over 32-64 bytes fits a 2048-bit key with room to
// spare, and the private half is generated in and never leaves the TPM — the
// provider cannot export a key, so the guarantee is the provider's, not a flag.
//
// A different key from the signer, deliberately: signing and decryption never
// share a key. Named and persisted, never overwritten: creation without
// NCRYPT_OVERWRITE_KEY_FLAG fails on an existing name, so a misread status cannot
// replace the key a stored seed is wrapped under.
//
// WRITTEN BUT NOT YET RUN ON WINDOWS. For that reason a seed ALREADY stored
// unwrapped is NOT wrapped under this key on upgrade unless the operator opts in
// (see mayWrapAnExistingSeed); a NEW seed is wrapped, because there is nothing
// older to lose. It compiles for windows/amd64 and
// windows/arm64; no Windows machine was available to execute it. What would
// prove it is seedwrap_windows_test.go on a Windows 11 machine with a TPM: wrap,
// drop the handle, unwrap, and check a wrong-user or deleted key fails.
//
// OAEP uses SHA-256; if the TPM refuses to decrypt with it, Wrap falls back to
// SHA-1, whose use in OAEP is not weakened by SHA-1's collision weakness, and
// records which in the first byte. The round trip happens at wrap time either
// way (storeSeedAs repeats it), so a seed is never stored under a padding the
// TPM cannot open.

import (
	"bytes"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tpmSeedWrapKeyName = "IdentityAgentSeedWrapKey.v1"

const (
	ncryptAllowDecryptFlag = 0x00000001 // NCRYPT_ALLOW_DECRYPT_FLAG
	ncryptPadOAEPFlag      = 0x00000004 // NCRYPT_PAD_OAEP_FLAG
)

var (
	procSetProperty = ncrypt.NewProc("NCryptSetProperty")
	procEncrypt     = ncrypt.NewProc("NCryptEncrypt")
	procDecrypt     = ncrypt.NewProc("NCryptDecrypt")
)

// bcryptOAEPPaddingInfo is BCRYPT_OAEP_PADDING_INFO.
type bcryptOAEPPaddingInfo struct {
	algID   *uint16
	label   *byte
	cbLabel uint32
}

type tpmSeedWrapper struct {
	proof provenOnce
	// keyName is the key inside the provider this wrapper uses: the device-wide
	// one, or a profile's own (ADR-074 section 3).
	keyName string
}

// seedKeyMu serialises opening-or-creating the key across every caller in the
// process (Available, Wrap, Unwrap), so two first calls cannot both find no key
// and both try to create it.
var seedKeyMu sync.Mutex

func newPlatformSeedWrapper() SeedWrapper { return &tpmSeedWrapper{keyName: tpmSeedWrapKeyName} }

// KeyNameFor and ForKey make this a per-profile wrapper (PerProfileKeys): the
// profile's own TPM key, named inside the Platform Crypto Provider.
func (w *tpmSeedWrapper) KeyNameFor(profile string) string {
	return ProfileKeyName(tpmSeedWrapKeyName, profile)
}

func (w *tpmSeedWrapper) ForKey(name string) SeedWrapper { return &tpmSeedWrapper{keyName: name} }

func (w *tpmSeedWrapper) Scheme() string { return tpmSeedScheme }

// Available is proven: the key is opened or made, and a probe is wrapped and
// opened. A machine with no TPM fails at the provider and reports false. The
// proof runs once per wrapper, so concurrent first calls do not race.
func (w *tpmSeedWrapper) Available() bool {
	return w.proof.do(func() bool {
		probe := bytes.Repeat([]byte{0x5a}, 32)
		blob, err := w.Wrap(probe)
		if err != nil {
			return false
		}
		back, err := w.Unwrap(blob)
		return err == nil && bytes.Equal(back, probe)
	})
}

// openSeedKey opens the wrapping key, making it the first time. The caller frees
// the key and the provider.
func openSeedKey(keyName string) (provider, key windows.Handle, err error) {
	seedKeyMu.Lock()
	defer seedKeyMu.Unlock()
	provider, err = openProvider()
	if err != nil {
		return 0, 0, err
	}
	free := func() { procFreeObject.Call(uintptr(provider)) }
	name, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		free()
		return 0, 0, err
	}
	r, _, _ := procOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)), 0, 0)
	switch {
	case r == 0:
		return provider, key, nil
	case meansNoKeyYet(uint32(r)):
		key, err = createSeedWrapKey(provider, name)
		if err != nil {
			free()
			return 0, 0, err
		}
		return provider, key, nil
	default:
		free()
		return 0, 0, fmt.Errorf("the seed-wrapping key could not be opened (0x%X)", uint32(r))
	}
}

func createSeedWrapKey(provider windows.Handle, name *uint16) (windows.Handle, error) {
	algorithm, err := windows.UTF16PtrFromString("RSA")
	if err != nil {
		return 0, err
	}
	var key windows.Handle
	if r, _, _ := procCreatePersistedKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algorithm)), uintptr(unsafe.Pointer(name)), 0, 0); r != 0 {
		return 0, fmt.Errorf("the seed-wrapping key could not be created (0x%X)", uint32(r))
	}
	set := func(prop string, v uint32) error {
		p, err := windows.UTF16PtrFromString(prop)
		if err != nil {
			return err
		}
		if r, _, _ := procSetProperty.Call(uintptr(key), uintptr(unsafe.Pointer(p)),
			uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v), 0); r != 0 {
			return fmt.Errorf("setting %q on the seed-wrapping key failed (0x%X)", prop, uint32(r))
		}
		return nil
	}
	// No export policy is set: the provider cannot make an exportable key.
	if err := set("Length", tpmWrapKeyBits); err != nil {
		procFreeObject.Call(uintptr(key))
		return 0, err
	}
	if err := set("Key Usage", ncryptAllowDecryptFlag); err != nil {
		procFreeObject.Call(uintptr(key))
		return 0, err
	}
	if r, _, _ := procFinalizeKey.Call(uintptr(key), 0); r != 0 {
		procFreeObject.Call(uintptr(key))
		return 0, fmt.Errorf("the TPM would not finalise the seed-wrapping key (0x%X)", uint32(r))
	}
	return key, nil
}

func oaepInfo(hash byte) (*bcryptOAEPPaddingInfo, error) {
	name := "SHA256"
	if hash == tpmWrapSHA1 {
		name = "SHA1"
	}
	alg, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	return &bcryptOAEPPaddingInfo{algID: alg}, nil
}

func (w *tpmSeedWrapper) encrypt(key windows.Handle, hash byte, plain []byte) ([]byte, error) {
	pad, err := oaepInfo(hash)
	if err != nil {
		return nil, err
	}
	out := make([]byte, tpmWrapCipherLen)
	var n uint32
	if r, _, _ := procEncrypt.Call(uintptr(key), uintptr(unsafe.Pointer(&plain[0])), uintptr(len(plain)),
		uintptr(unsafe.Pointer(pad)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(unsafe.Pointer(&n)), ncryptPadOAEPFlag); r != 0 {
		return nil, fmt.Errorf("the seed could not be encrypted to the TPM key (0x%X)", uint32(r))
	}
	return out[:n], nil
}

func (w *tpmSeedWrapper) decrypt(key windows.Handle, hash byte, ct []byte) ([]byte, error) {
	pad, err := oaepInfo(hash)
	if err != nil {
		return nil, err
	}
	out := make([]byte, tpmWrapCipherLen)
	var n uint32
	if r, _, _ := procDecrypt.Call(uintptr(key), uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)),
		uintptr(unsafe.Pointer(pad)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(unsafe.Pointer(&n)), ncryptPadOAEPFlag); r != 0 {
		return nil, fmt.Errorf("the TPM would not open the wrapped seed (0x%X)", uint32(r))
	}
	return out[:n], nil
}

func (w *tpmSeedWrapper) Wrap(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty seed")
	}
	provider, key, err := openSeedKey(w.keyName)
	if err != nil {
		return nil, err
	}
	defer procFreeObject.Call(uintptr(provider))
	defer procFreeObject.Call(uintptr(key))

	var lastErr error
	for _, hash := range []byte{tpmWrapSHA256, tpmWrapSHA1} {
		ct, err := w.encrypt(key, hash, plain)
		if err != nil {
			lastErr = err
			continue
		}
		// The TPM has to be able to open what it sealed under this padding.
		back, err := w.decrypt(key, hash, ct)
		if err != nil || !bytes.Equal(back, plain) {
			lastErr = fmt.Errorf("OAEP/%d did not round-trip through the TPM: %v", hash, err)
			continue
		}
		return packTPMWrap(hash, ct)
	}
	return nil, lastErr
}

func (w *tpmSeedWrapper) Unwrap(blob []byte) ([]byte, error) {
	hash, ct, err := unpackTPMWrap(blob)
	if err != nil {
		return nil, err
	}
	provider, key, err := openSeedKey(w.keyName)
	if err != nil {
		return nil, err
	}
	defer procFreeObject.Call(uintptr(provider))
	defer procFreeObject.Call(uintptr(key))
	return w.decrypt(key, hash, ct)
}
