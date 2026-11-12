//go:build windows

package secureenclave

// A machine's key on Windows, held by the TPM.
//
// This was a stub whose Available() returned false, so no Windows machine could
// ever act for an identity — while the capability detector next door already
// created a real key on the Microsoft Platform Crypto Provider to prove the
// hardware works. The difficult part was written and used only to answer "could
// this machine protect a key", never to hold one.
//
// P-256, not Ed25519, and that is not a compromise. No shipping TPM implements
// Ed25519; the TCG registry defines no Edwards curve, and this provider does RSA
// and the NIST curves and nothing else. What the curve buys is non-extractability
// — the key cannot be carried to another machine — which a seed sealed to the TPM
// and unwrapped into memory would give up while keeping one curve.
//
// This is the key a machine signs its own requests with. A KERI identity prefix
// stays Ed25519 wherever it lives, INCLUDING on a machine that holds one; the
// distinction is what the key is for, not what kind of thing holds it.
//
// WRITTEN BUT NOT YET RUN ON WINDOWS. It compiles for windows/amd64 and follows
// the provider's documented contract, and no Windows machine was available to
// execute it. What would prove it is the test beside the macOS one: create,
// restart, reopen, sign, and verify against the published key — plus the assert
// that distinguishes a real TPM key from a software one, which is that asking
// this provider for an exportable key fails with NTE_NOT_SUPPORTED rather than
// succeeding.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

func newDarwinSecureEnclaveSigner(dataDir string) PlatformSigner { return nil }
func newStrongBoxSigner() PlatformSigner                         { return nil }

var (
	procOpenKey   = ncrypt.NewProc("NCryptOpenKey")
	procExportKey = ncrypt.NewProc("NCryptExportKey")
	procSignHash  = ncrypt.NewProc("NCryptSignHash")
	procDeleteKey = ncrypt.NewProc("NCryptDeleteKey")
)

// ncryptSilentFlag is NCRYPT_SILENT_FLAG: the provider may not show UI. Passed on
// every call that can reach a key with an authorization value, so a core with no
// desktop to show it on fails with a status instead of waiting for a prompt.
const ncryptSilentFlag = 0x00000040

func init() {
	// A TPM key made for a profile is evidence the profile was gated, even when
	// every file that said so is gone.
	aHardwareKeyOfThisProfileExists = func(dataDir, profileID string) bool {
		return theProfilesTPMKeyExists(ProfileKeyName(machineKeyName, profileID))
	}
}

// theProfilesTPMKeyExists opens the named key without using it. A status that
// is not "there is no such key" counts as existing: a key that cannot be asked
// about is not shown to be absent.
func theProfilesTPMKeyExists(name string) bool {
	provider, err := openProvider()
	if err != nil {
		return false
	}
	defer procFreeObject.Call(uintptr(provider))
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	var key windows.Handle
	r, _, _ := procOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(n)), 0, ncryptSilentFlag)
	if r == 0 {
		procFreeObject.Call(uintptr(key))
		return true
	}
	return !meansNoKeyYet(uint32(r))
}

// machineKeyName is what this agent's key is called inside the provider.
//
// Stable on purpose: reopening it by name is how the machine is the same machine
// after a restart, which is the whole requirement for a key a grant was made to.
const machineKeyName = "IdentityAgentMachineKey.v1"

// The provider has three ways of saying "there is no key of that name yet",
// which is the ordinary first-run answer rather than a fault.
//
// Only NTE_BAD_KEYSET was handled. The other two reached the generic branch and
// were reported as "this machine's key could not be opened", so a machine that
// had simply never made one would refuse to act for an identity and give a
// reason that sounds like broken hardware.
//
// Taken from x/sys/windows rather than transcribed. This file already imports
// that package, and three hand-typed hex values are three chances to mistype a
// status code in a way nothing on this platform would catch.

// meansNoKeyYet reports whether the provider is saying there is no key of that
// name, rather than that something is wrong.
//
// SAFE TO WIDEN because creating cannot clobber. createMachineKey calls
// NCryptCreatePersistedKey with no NCRYPT_OVERWRITE_KEY_FLAG, so if a key of
// this name does exist, creation fails with NTE_EXISTS and ensure returns an
// error. A status wrongly classified here therefore changes which error a
// person sees; it cannot replace a key a grant was made to.
//
// Access-denied is NTE_PERM and is deliberately NOT in this set: a key that
// exists but cannot be opened is a fault to report, not a first run.
func meansNoKeyYet(code uint32) bool {
	switch code {
	case uint32(windows.NTE_BAD_KEYSET), uint32(windows.NTE_NO_KEY), uint32(windows.NTE_NOT_FOUND):
		return true
	}
	return false
}

// bcryptECDSAPublicP256Magic is the magic number at the head of a
// BCRYPT_ECCKEY_BLOB holding a P-256 public key.
//
// Checked rather than assumed. The coordinate size alone does not identify a
// curve: several curves have 32-byte coordinates, so a blob for one of those
// would pass the size check and be assembled into a point that is not on P-256.
// The failure would then surface much later as a signature that never verifies,
// with nothing pointing back here.
const bcryptECDSAPublicP256Magic = 0x31534345

type tpmSigner struct {
	mu     sync.Mutex
	opened bool
	pub    []byte
	// dataDir is the profile this key belongs to, "" for the machine's own key
	// with no profile. keyName is the key inside the provider: the device-wide
	// name, or the profile's own when it has a gate (ADR-074 section 3).
	dataDir string
	keyName string
	lastErr error
}

func (s *tpmSigner) whyUnavailable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

func newTPMSigner() PlatformSigner { return &tpmSigner{keyName: machineKeyName} }

// forProfileAt is the controller key of the profile whose data is at dataDir:
// a key of its own, and under the gate's authorization value when the profile
// has a gate. NewPlatformSigner asks for it; a profile with no gate gets the
// device-wide key, as before.
func (s *tpmSigner) forProfileAt(dataDir string) PlatformSigner {
	return &tpmSigner{dataDir: dataDir, keyName: controllerKeyNameFor(machineKeyName, dataDir)}
}

// authorization is the TPM authorization value of this key: HKDF(GK, "tpm-auth")
// for a profile with a gate, nil for one without. A locked profile is
// ErrIdentityLocked, so the TPM is not asked.
func (s *tpmSigner) authorization() ([]byte, error) {
	if s.dataDir == "" {
		return nil, nil
	}
	return tpmAuthorizationFor(s.dataDir)
}

// stillOpen refuses once the profile has locked, even to a signer that opened
// the key before.
func (s *tpmSigner) stillOpen() error {
	if s.dataDir == "" {
		return nil
	}
	_, _, err := theGateForThisSeed(s.dataDir)
	return err
}

func (s *tpmSigner) Platform() string { return "tpm2" }
func (s *tpmSigner) Label() string    { return "TPM 2.0 (Platform Crypto Provider)" }

func (s *tpmSigner) Available() bool { return s.ensure() == nil }

// openProvider is the same handle the detector opens, asked for again here
// rather than shared, because a signer that outlives a probe should not depend
// on the probe having run.
func openProvider() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("Microsoft Platform Crypto Provider")
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	if r, _, _ := procOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(name)), 0); r != 0 {
		return 0, fmt.Errorf("the platform crypto provider would not open (0x%X)", uint32(r))
	}
	return h, nil
}

// ensure opens this machine's key, creating it the first time.
//
// The key is PERSISTED and never exportable. The provider does not implement
// export at all — asking for an exportable key fails rather than quietly giving
// one — so the private half cannot leave the TPM even for code running as this
// user. What that same code CAN do is ask the TPM to sign, because the provider
// isolates by user account rather than by process. The key cannot be taken; its
// use can be borrowed by something already running as you. That is the same
// property the Secure Enclave path has on macOS, which is why both platforms can
// be described the same way instead of two different ways.
func (s *tpmSigner) ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opened {
		return s.stillOpen()
	}
	err := s.open()
	s.lastErr = err
	return err
}

func (s *tpmSigner) open() error {
	// The authorization value first: a locked profile never reaches the TPM.
	auth, err := s.authorization()
	if err != nil {
		return err
	}
	defer zero(auth)

	provider, err := openProvider()
	if err != nil {
		return err
	}
	defer procFreeObject.Call(uintptr(provider))

	name, err := windows.UTF16PtrFromString(s.keyName)
	if err != nil {
		return err
	}

	var key windows.Handle
	r, _, _ := procOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)), 0, ncryptSilentFlag)
	created := false
	if meansNoKeyYet(uint32(r)) {
		if key, err = createMachineKey(provider, name, auth); err != nil {
			return err
		}
		created = true
	} else if r != 0 {
		return fmt.Errorf("%w: this machine's key could not be opened (0x%X)",
			errAHardwareKeyExistsAndWillNotOpen, uint32(r))
	}
	defer procFreeObject.Call(uintptr(key))

	pub, err := exportPublic(key)
	if err != nil {
		return err
	}
	if auth != nil {
		// A gated profile uses only a key it made. The core records the public
		// key of the one it creates, under the gate key, and refuses any other:
		// same-user code can make a key of this name with no authorization value.
		if created {
			if s.keyName != machineKeyName && theProfilesTPMKeyExists(machineKeyName) {
				// ADR-074 section 3: a profile's key is a new key, so the root
				// device's grant to the device-wide one no longer matches.
				log.Printf("[secureenclave] this computer made a controller key of its own for this identity; the device-wide key it used before is kept and is no longer the one it signs with, so its root device must grant it again")
			}
			if err := recordTheControllerKey(s.dataDir, "tpm2", s.keyName, pub); err != nil {
				// Not recorded is not ours: take it back so a retry can make one.
				procDeleteKey.Call(uintptr(key), 0)
				return fmt.Errorf("the controller key could not be recorded: %w", err)
			}
		} else if err := theControllerKeyIsTheOneWeMade(s.dataDir, s.keyName, pub); err != nil {
			return fmt.Errorf("%w: %w", errAHardwareKeyExistsAndWillNotOpen, err)
		}
	}
	s.pub, s.opened = pub, true
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func createMachineKey(provider windows.Handle, name *uint16, auth []byte) (windows.Handle, error) {
	algorithm, err := windows.UTF16PtrFromString("ECDSA_P256")
	if err != nil {
		return 0, err
	}
	var key windows.Handle
	if r, _, _ := procCreatePersistedKey.Call(
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algorithm)),
		uintptr(unsafe.Pointer(name)), // named, so it persists
		0,
		// NO NCRYPT_OVERWRITE_KEY_FLAG, AND THAT ABSENCE IS LOAD-BEARING. It is
		// what makes it safe for meansNoKeyYet to classify a status as "no key
		// yet": if a key of this name does exist, creation fails with NTE_EXISTS
		// rather than replacing it. Adding the flag for convenience would mean a
		// misread status silently mints a new key -- and a machine with a new key
		// is a new machine, so every grant made to it is void.
		0,
	); r != 0 {
		return 0, fmt.Errorf("this machine's key could not be created (0x%X)", uint32(r))
	}
	// Nothing sets an export policy. The default is no export, and this provider
	// cannot produce an exportable key even when asked — so the guarantee comes
	// from the provider rather than from a flag somebody could change.
	//
	// A profile's key has an authorization value, set before it is finalised: the
	// TPM then refuses to sign without it and counts failures itself (ADR-074).
	if auth != nil {
		if err := setUsageAuth(key, auth); err != nil {
			procFreeObject.Call(uintptr(key))
			return 0, err
		}
	}
	if r, _, _ := procFinalizeKey.Call(uintptr(key), 0); r != 0 {
		procFreeObject.Call(uintptr(key))
		return 0, fmt.Errorf("the TPM would not finalise this machine's key (0x%X)", uint32(r))
	}
	return key, nil
}

// exportPublic returns the key as an X9.63 uncompressed point, matching what the
// macOS signer returns, so everything above this is one code path.
//
// The provider hands back a BCRYPT_ECCKEY_BLOB: a magic number, the coordinate
// size, then X and then Y. The point is assembled here rather than passing the
// blob upwards, because a blob shape is this platform's business.
func exportPublic(key windows.Handle) ([]byte, error) {
	blobType, err := windows.UTF16PtrFromString("ECCPUBLICBLOB")
	if err != nil {
		return nil, err
	}
	var need uint32
	if r, _, _ := procExportKey.Call(uintptr(key), 0, uintptr(unsafe.Pointer(blobType)),
		0, 0, 0, uintptr(unsafe.Pointer(&need)), 0); r != 0 {
		return nil, fmt.Errorf("this machine's public key could not be sized (0x%X)", uint32(r))
	}
	buf := make([]byte, need)
	if r, _, _ := procExportKey.Call(uintptr(key), 0, uintptr(unsafe.Pointer(blobType)),
		0, uintptr(unsafe.Pointer(&buf[0])), uintptr(need),
		uintptr(unsafe.Pointer(&need)), 0); r != 0 {
		return nil, fmt.Errorf("this machine's public key could not be read (0x%X)", uint32(r))
	}
	return pointFromECCBlob(buf)
}

// pointFromECCBlob turns a BCRYPT_ECCKEY_BLOB into an X9.63 uncompressed point.
//
// Separated from the call that obtains the blob so it can be tested without a
// TPM. Every check below is on data the provider handed back, so a test can
// exercise all of them; none of it needs hardware, and requiring hardware is why
// this went unchecked.
func pointFromECCBlob(buf []byte) ([]byte, error) {
	if len(buf) < 8 {
		return nil, fmt.Errorf("the public key blob is %d bytes, too short to describe a key", len(buf))
	}
	// THE MAGIC, NOT JUST THE SIZE. A coordinate size of 32 does not identify a
	// curve — several have 32-byte coordinates — so without this a blob for a
	// different curve is assembled into a point that is not on P-256, and the
	// first thing to notice is a signature that never verifies, far from here.
	if magic := binary.LittleEndian.Uint32(buf[0:4]); magic != bcryptECDSAPublicP256Magic {
		return nil, fmt.Errorf("this is not a P-256 public key blob (magic %#x)", magic)
	}
	size := int(binary.LittleEndian.Uint32(buf[4:8]))
	if size != 32 || len(buf) < 8+2*size {
		return nil, fmt.Errorf("expected a P-256 key with 32-byte coordinates, got %d in %d bytes",
			size, len(buf))
	}
	out := make([]byte, 1+2*size)
	out[0] = 0x04
	copy(out[1:], buf[8:8+2*size])
	return out, nil
}

func (s *tpmSigner) PublicKey() ([]byte, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	return s.pub, nil
}

// Sign returns raw r||s, which is what this provider produces and what CESR's
// secp256r1 signature code carries — no DER anywhere on this path.
//
// The message is hashed here because NCryptSignHash signs a digest rather than a
// message. SHA-256, matching what the macOS signer hashes with, so a signature
// from either platform is checked the same way.
func (s *tpmSigner) Sign(data []byte) ([]byte, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("nothing to sign")
	}
	auth, err := s.authorization()
	if err != nil {
		return nil, err
	}
	defer zero(auth)

	provider, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer procFreeObject.Call(uintptr(provider))

	name, err := windows.UTF16PtrFromString(s.keyName)
	if err != nil {
		return nil, err
	}
	var key windows.Handle
	if r, _, _ := procOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)), 0, ncryptSilentFlag); r != 0 {
		return nil, fmt.Errorf("this machine's key could not be opened to sign (0x%X)", uint32(r))
	}
	defer procFreeObject.Call(uintptr(key))
	// The key opened by name now is the one that was checked when it was first
	// opened: a key swapped in between is refused before the TPM is asked to sign.
	if now, err := exportPublic(key); err != nil || !bytes.Equal(now, s.pub) {
		return nil, fmt.Errorf("%w: the key of this name is not the one that was opened", ErrControllerKeyNotOurs)
	}
	if auth != nil {
		if err := supplyUsageAuth(key, auth); err != nil {
			return nil, err
		}
	}

	sum := sha256.Sum256(data)
	var need uint32
	if r, _, _ := procSignHash.Call(uintptr(key), 0,
		uintptr(unsafe.Pointer(&sum[0])), uintptr(len(sum)),
		0, 0, uintptr(unsafe.Pointer(&need)), ncryptSilentFlag); r != 0 {
		return nil, fmt.Errorf("the TPM would not size a signature (0x%X)", uint32(r))
	}
	sig := make([]byte, need)
	if r, _, _ := procSignHash.Call(uintptr(key), 0,
		uintptr(unsafe.Pointer(&sum[0])), uintptr(len(sum)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(need),
		uintptr(unsafe.Pointer(&need)), ncryptSilentFlag); r != 0 {
		return nil, fmt.Errorf("the TPM would not sign (0x%X)", uint32(r))
	}
	if int(need) != 64 {
		return nil, fmt.Errorf("expected 64 bytes of raw r||s from a P-256 key, got %d", need)
	}
	return sig[:need], nil
}

// The one NCrypt property that carries a TPM key's authorization value. The core
// does not compute the digest the TPM keeps: it gives the provider the value as
// NCRYPT_PIN_PROPERTY, both when the key is made (before it is finalised) and
// when it is used, and the provider derives the authorization from it the same
// way both times. An earlier version set PCP_USAGEAUTH to a SHA-1 the core
// computed over the ASCII text and supplied the text as UTF-16 at use, which
// agrees only if the provider hashes it exactly that way; Microsoft's samples
// hash the UTF-16LE string without its terminator.
//
// UNVERIFIED ON A TPM: that this provider accepts the property before
// finalisation, and refuses the wrong value and counts it. scripts/tpm-authorization-probe
// decides it on a real Windows machine (ADR-074 section 3).
const ncryptPinProperty = "SmartCardPin" // NCRYPT_PIN_PROPERTY, the value as a wide string

// setUsageAuth gives a key being made its authorization value.
func setUsageAuth(key windows.Handle, auth []byte) error {
	return setThePin(key, auth, "the TPM would not take the controller key's authorization value")
}

// supplyUsageAuth gives an opened key the authorization value it needs to sign.
func supplyUsageAuth(key windows.Handle, auth []byte) error {
	return setThePin(key, auth, "the TPM would not take the authorization value to sign")
}

// setThePin hands the provider the value as the wide string it takes, with its
// terminator, and wipes every copy of it that this function made.
func setThePin(key windows.Handle, auth []byte, failure string) error {
	wide := tpmUsageAuthWide(auth)
	defer func() {
		for i := range wide {
			wide[i] = 0
		}
	}()
	p, err := windows.UTF16PtrFromString(ncryptPinProperty)
	if err != nil {
		return err
	}
	if r, _, _ := procSetProperty.Call(uintptr(key), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)*2), ncryptSilentFlag); r != 0 {
		return fmt.Errorf("%s (0x%X)", failure, uint32(r))
	}
	return nil
}
