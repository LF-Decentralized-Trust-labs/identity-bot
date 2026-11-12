//go:build darwin && cgo && sepblob

// A machine's key, held by the Secure Enclave without the keychain.
//
// This replaces the Security.framework signer on macOS. That one asks the
// keychain to persist the enclave key, which needs a keychain access group,
// which needs an entitlement authorised by a provisioning profile, which needs
// an app-like bundle to embed the profile in. Our backend is a bare executable
// inside the app's Resources, so it has nowhere to put a profile and the request
// can only ever fail with errSecMissingEntitlement.
//
// The way out is to notice what the keychain was being asked to do. A Secure
// Enclave key is never stored in the enclave; the enclave wraps it and returns a
// blob only that chip can unwrap. The keychain was holding that blob. Holding it
// ourselves keeps the same hardware and the same fact that the private half never
// leaves the chip, without any of the apparatus.
//
// It does NOT keep everything the keychain offered. A keychain item has a
// per-application access control list; a file at 0600 does not, so any process
// running as this person can read it and ask the enclave to sign. The key cannot
// be taken; its use can be borrowed locally. That is a real difference and it is
// recorded here rather than left for somebody to discover.
//
// Built behind a tag because it needs a Swift library compiled first: only
// CryptoKit exposes the wrapped blob, and cgo cannot compile Swift. The macOS
// build scripts compile it and pass the tag. Without the tag the older signer is
// used, and it refuses honestly rather than falling back to something weaker.
package secureenclave

/*
#cgo LDFLAGS: -lsep -framework CryptoKit -framework Foundation -L/usr/lib/swift -lswiftCore
#include <stdlib.h>
#include <stddef.h>
int sep_available(void);
int sep_blob_size(void);
int sep_create(unsigned char *out, size_t cap, size_t *n);
int sep_public(const unsigned char *blob, size_t blen, unsigned char *out, size_t cap, size_t *n);
int sep_sign(const unsigned char *blob, size_t blen, const unsigned char *msg, size_t mlen,
             unsigned char *out, size_t cap, size_t *n);
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"identity-agent-core/atomicfile"
)

// sepEnvelope is how the wrapped key sits on disk.
//
// Self-describing, and carrying the length on purpose. CryptoKit's restore does
// not return an error on a blob of the wrong size — it TRAPS, inside a `try!`,
// and takes the process with it. So the length is recorded when the key is made
// and checked before the blob is ever handed back, because afterwards there is
// nothing left to check it with.
type sepEnvelope struct {
	V    int    `json:"v"`
	Kind string `json:"kind"`
	Len  int    `json:"len"`
	Blob string `json:"blob"`
	// Gate names the gate layer Blob is sealed under (ADR-074 section 3): the
	// blob is ciphertext on disk, and Len is the length of the blob inside it.
	// Empty on a key made before the profile had a gate.
	Gate string `json:"gate,omitempty"`
}

type sepSigner struct {
	mu      sync.Mutex
	dataDir string
	blob    []byte
	loaded  bool
	// lastErr is why ensure last failed, for NewPlatformSigner to report when it
	// refuses instead of falling through to the software signer.
	lastErr error
}

// newDarwinSecureEnclaveSigner is the name NewPlatformSigner already calls, so
// selecting this implementation is a build tag rather than a branch. Exactly one
// of the two darwin enclave signers is ever compiled in.
func newDarwinSecureEnclaveSigner(dataDir string) PlatformSigner { return newSepSigner(dataDir) }

func newSepSigner(dataDir string) PlatformSigner { return &sepSigner{dataDir: dataDir} }

func (s *sepSigner) Platform() string { return "secure_enclave" }
func (s *sepSigner) Label() string    { return "Apple Secure Enclave" }

func (s *sepSigner) path() string {
	return filepath.Join(s.dataDir, "secureenclave", "machine_key.sep")
}

func (s *sepSigner) Available() bool {
	if C.sep_available() != 1 {
		return false
	}
	err := s.ensure()
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
	return err == nil
}

func (s *sepSigner) whyUnavailable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// ensure loads the machine's key, or mints one the first time.
//
// Written atomically, and 0600. The blob cannot be used on any other machine —
// the wrapping key derives from an identifier fused into this processor — but on
// THIS machine anything running as this user can use it, because a file is all
// that guards it. That is the same property the Windows platform provider has,
// where isolation is by account rather than by process, so both platforms tell
// the same story: the key cannot be taken, but its use can be borrowed by
// something already running as you.
func (s *sepSigner) ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		return nil
	}
	existing, needsGate, rerr := s.read()
	if errors.Is(rerr, ErrIdentityLocked) {
		// Locked: the blob is ciphertext and there is no key. Nothing is set
		// aside and nothing is made: a locked profile's key is not replaced.
		return rerr
	}
	if rerr == nil {
		// USABLE, not merely well-formed. A blob wrapped by a DIFFERENT chip is
		// the right size and passes every check above, because the wrapped size is
		// the same on every Mac — so a data directory restored from a backup, or
		// copied to other hardware, yields a signer that reports itself available
		// and then fails every signature for the life of the installation, with no
		// path that ever re-mints. Asking the enclave to use it once is the only
		// thing that distinguishes our key from somebody else's.
		if _, uerr := publicFrom(existing); uerr == nil {
			if needsGate {
				// Made before the profile had a gate: seal it now that it does.
				if err := s.write(existing); err != nil {
					return fmt.Errorf("the controller key could not be sealed under the gate key: %w", err)
				}
			}
			s.blob, s.loaded = existing, true
			return nil
		}
		// KEPT, NOT DELETED. This machine cannot use it, but it is a real key
		// belonging to whichever machine made it, and a file that turns out to
		// matter is not one to remove on a guess.
		aside := s.path() + ".not-this-machine"
		if err := os.Rename(s.path(), aside); err != nil {
			return fmt.Errorf("this machine holds a key it cannot use and could not set "+
				"it aside: %w", err)
		}
	}

	buf := make([]byte, 1024)
	var n C.size_t
	rc := C.sep_create((*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &n)
	if rc != 0 {
		return fmt.Errorf("the secure enclave would not make a key for this machine (%d)", int(rc))
	}
	blob := make([]byte, int(n))
	copy(blob, buf[:int(n)])

	data, err := s.envelopeFor(blob)
	if err != nil {
		return err
	}
	p := s.path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	// Written to a UNIQUE temporary name and flushed before the rename.
	//
	// A fixed name is not exclusive, and this mutex is per process: two cores over
	// one data directory would interleave on the same temp file, each keep its own
	// key in memory, and one would silently win on disk. After a restart the
	// machine would have a different identifier than the grant made to it, which
	// is a machine that has quietly become a different machine.
	//
	// The flush matters for the same reason: a rename that lands before the bytes
	// do leaves an empty file, and the next start mints another identity.
	//
	// Create-or-fail, so a key minted concurrently is adopted rather than
	// overwritten. Losing that race is an ordinary outcome, not an error: the
	// other process's key is just as much this machine's key, and the one thing
	// that must not happen is two of them.
	if err := atomicfile.Create(p, data, 0o600); err != nil {
		if adopted, _, rerr := s.read(); rerr == nil {
			s.blob, s.loaded = adopted, true
			return nil
		}
		return fmt.Errorf("this machine's key could not be stored: %w", err)
	}
	s.blob, s.loaded = blob, true
	return nil
}

// read returns the stored blob, refusing anything whose length disagrees with
// what this enclave produces.
//
// A profile with a gate keeps the blob sealed under its gate key (ADR-074
// section 3): a locked one is ErrIdentityLocked, whatever is on disk, and one
// written before the gate is served with needsGate set so the caller seals it.
func (s *sepSigner) read() (blob []byte, needsGate bool, err error) {
	data, err := os.ReadFile(s.path())
	if err != nil {
		return nil, false, err
	}
	var env sepEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, false, fmt.Errorf("the machine key envelope could not be read: %w", err)
	}
	stored, err := base64.StdEncoding.DecodeString(env.Blob)
	if err != nil {
		return nil, false, fmt.Errorf("the machine key is not valid base64: %w", err)
	}
	if len(stored) == 0 {
		return nil, false, fmt.Errorf("the machine key file holds no key")
	}
	blob, needsGate, err = openFromTheGate(s.dataDir, stored, env.Gate)
	if err != nil {
		return nil, false, err
	}
	if len(blob) != env.Len {
		return nil, false, fmt.Errorf("the machine key is %d bytes where its envelope says %d",
			len(blob), env.Len)
	}
	// The guard that matters: a blob this enclave would not accept must never
	// reach it, because being refused is not one of the outcomes on offer.
	if want := int(C.sep_blob_size()); want > 0 && len(blob) != want {
		return nil, false, fmt.Errorf("the machine key is %d bytes where this enclave makes %d",
			len(blob), want)
	}
	return blob, needsGate, nil
}

// envelopeFor is the file's bytes for blob: sealed under the profile's gate key
// when it has one, and refusing when the profile is locked.
func (s *sepSigner) envelopeFor(blob []byte) ([]byte, error) {
	sealed, scheme, err := sealForTheGate(s.dataDir, blob)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sepEnvelope{V: 1, Kind: "sep-p256-signing", Len: len(blob),
		Blob: base64.StdEncoding.EncodeToString(sealed), Gate: scheme})
}

// write replaces the stored key with blob under the profile's current gate.
func (s *sepSigner) write(blob []byte) error {
	data, err := s.envelopeFor(blob)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path()), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(s.path(), data, 0o600)
}

// stillOpen refuses once the profile has locked, even to a signer that loaded
// the key before: the blob held in memory is not a reason to keep signing.
func (s *sepSigner) stillOpen() error {
	_, _, err := theGateForThisSeed(s.dataDir)
	return err
}

func (s *sepSigner) PublicKey() ([]byte, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if err := s.stillOpen(); err != nil {
		return nil, err
	}
	return publicFrom(s.blob)
}

// publicFrom asks the enclave to unwrap a blob and hand back the public half.
//
// Separate so that loading can use it as a usability check without duplicating
// the call, which is what stops a blob from another machine being accepted.
func publicFrom(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("there is no key to read")
	}
	out := make([]byte, 128)
	var n C.size_t
	rc := C.sep_public((*C.uchar)(unsafe.Pointer(&blob[0])), C.size_t(len(blob)),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &n)
	if rc != 0 {
		return nil, fmt.Errorf("this enclave cannot use that key (%d) — it was wrapped "+
			"by a different machine", int(rc))
	}
	return out[:int(n)], nil
}

// Sign returns raw r||s, which is what CESR's secp256r1 signature code carries.
// No DER unwrapping: CryptoKit offers the raw form directly, where
// Security.framework returns DER.
func (s *sepSigner) Sign(data []byte) ([]byte, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if err := s.stillOpen(); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("nothing to sign")
	}
	out := make([]byte, 128)
	var n C.size_t
	rc := C.sep_sign((*C.uchar)(unsafe.Pointer(&s.blob[0])), C.size_t(len(s.blob)),
		(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &n)
	if rc != 0 {
		return nil, fmt.Errorf("this machine's key would not sign (%d)", int(rc))
	}
	return out[:int(n)], nil
}
