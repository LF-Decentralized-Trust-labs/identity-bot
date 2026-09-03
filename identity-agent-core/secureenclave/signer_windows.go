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
// Ed25519; the TCG algorithm registry defines no Edwards curve at all, and the
// platform provider does RSA and the NIST curves and nothing else. A machine key
// that insisted on Ed25519 is a key no hardware can hold, which is exactly how
// this file came to be a stub. Identities stay Ed25519 — this is the machine's
// own key, and it is never an identity anybody founds anything on.
//
// WRITTEN BUT NOT YET RUN ON WINDOWS. It compiles for windows/amd64 and follows
// the provider's documented contract, and no Windows machine was available to
// execute it. What would prove it is the test beside the macOS one: create,
// restart, reopen, sign, and verify against the published key — plus the assert
// that distinguishes a real TPM key from a software one, which is that asking
// this provider for an exportable key fails with NTE_NOT_SUPPORTED rather than
// succeeding.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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
)

// machineKeyName is what this agent's key is called inside the provider.
//
// Stable on purpose: reopening it by name is how the machine is the same machine
// after a restart, which is the whole requirement for a key a grant was made to.
const machineKeyName = "IdentityAgentMachineKey.v1"

// ntStatusNotFound is NTE_BAD_KEYSET — the provider saying there is no key of
// that name yet, which is the ordinary first-run answer rather than a fault.
const ntStatusNotFound = 0x80090016

type tpmSigner struct {
	mu     sync.Mutex
	opened bool
	pub    []byte
}

func newTPMSigner() PlatformSigner { return &tpmSigner{} }

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
		return nil
	}

	provider, err := openProvider()
	if err != nil {
		return err
	}
	defer procFreeObject.Call(uintptr(provider))

	name, err := windows.UTF16PtrFromString(machineKeyName)
	if err != nil {
		return err
	}

	var key windows.Handle
	r, _, _ := procOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)), 0, 0)
	if uint32(r) == ntStatusNotFound {
		if key, err = createMachineKey(provider, name); err != nil {
			return err
		}
	} else if r != 0 {
		return fmt.Errorf("this machine's key could not be opened (0x%X)", uint32(r))
	}
	defer procFreeObject.Call(uintptr(key))

	pub, err := exportPublic(key)
	if err != nil {
		return err
	}
	s.pub, s.opened = pub, true
	return nil
}

func createMachineKey(provider windows.Handle, name *uint16) (windows.Handle, error) {
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
		0,
	); r != 0 {
		return 0, fmt.Errorf("this machine's key could not be created (0x%X)", uint32(r))
	}
	// Nothing sets an export policy. The default is no export, and this provider
	// cannot produce an exportable key even when asked — so the guarantee comes
	// from the provider rather than from a flag somebody could change.
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
	if len(buf) < 8 {
		return nil, fmt.Errorf("the public key blob is %d bytes, too short to describe a key", len(buf))
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

	provider, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer procFreeObject.Call(uintptr(provider))

	name, err := windows.UTF16PtrFromString(machineKeyName)
	if err != nil {
		return nil, err
	}
	var key windows.Handle
	if r, _, _ := procOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)), 0, 0); r != 0 {
		return nil, fmt.Errorf("this machine's key could not be opened to sign (0x%X)", uint32(r))
	}
	defer procFreeObject.Call(uintptr(key))

	sum := sha256.Sum256(data)
	var need uint32
	if r, _, _ := procSignHash.Call(uintptr(key), 0,
		uintptr(unsafe.Pointer(&sum[0])), uintptr(len(sum)),
		0, 0, uintptr(unsafe.Pointer(&need)), 0); r != 0 {
		return nil, fmt.Errorf("the TPM would not size a signature (0x%X)", uint32(r))
	}
	sig := make([]byte, need)
	if r, _, _ := procSignHash.Call(uintptr(key), 0,
		uintptr(unsafe.Pointer(&sum[0])), uintptr(len(sum)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(need),
		uintptr(unsafe.Pointer(&need)), 0); r != 0 {
		return nil, fmt.Errorf("the TPM would not sign (0x%X)", uint32(r))
	}
	if int(need) != 64 {
		return nil, fmt.Errorf("expected 64 bytes of raw r||s from a P-256 key, got %d", need)
	}
	return sig[:need], nil
}
