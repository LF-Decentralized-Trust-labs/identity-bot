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
// blob only that chip can unwrap. The keychain was only ever holding that blob.
// Holding it ourselves is the same mechanism with the middleman removed — same
// hardware, same guarantee that the private half never leaves the chip, and none
// of the apparatus.
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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"
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
}

type sepSigner struct {
	mu      sync.Mutex
	dataDir string
	blob    []byte
	loaded  bool
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
	return s.ensure() == nil
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
	if blob, err := s.read(); err == nil {
		s.blob, s.loaded = blob, true
		return nil
	}

	buf := make([]byte, 1024)
	var n C.size_t
	rc := C.sep_create((*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &n)
	if rc != 0 {
		return fmt.Errorf("the secure enclave would not make a key for this machine (%d)", int(rc))
	}
	blob := make([]byte, int(n))
	copy(blob, buf[:int(n)])

	env := sepEnvelope{V: 1, Kind: "sep-p256-signing", Len: len(blob),
		Blob: base64.StdEncoding.EncodeToString(blob)}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	p := s.path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	s.blob, s.loaded = blob, true
	return nil
}

// read returns the stored blob, refusing anything whose length disagrees with
// what this enclave produces.
func (s *sepSigner) read() ([]byte, error) {
	data, err := os.ReadFile(s.path())
	if err != nil {
		return nil, err
	}
	var env sepEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("the machine key envelope could not be read: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(env.Blob)
	if err != nil {
		return nil, fmt.Errorf("the machine key is not valid base64: %w", err)
	}
	if len(blob) != env.Len {
		return nil, fmt.Errorf("the machine key is %d bytes where its envelope says %d",
			len(blob), env.Len)
	}
	// The guard that matters: a blob this enclave would not accept must never
	// reach it, because being refused is not one of the outcomes on offer.
	if want := int(C.sep_blob_size()); want > 0 && len(blob) != want {
		return nil, fmt.Errorf("the machine key is %d bytes where this enclave makes %d",
			len(blob), want)
	}
	return blob, nil
}

func (s *sepSigner) PublicKey() ([]byte, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	out := make([]byte, 128)
	var n C.size_t
	rc := C.sep_public((*C.uchar)(unsafe.Pointer(&s.blob[0])), C.size_t(len(s.blob)),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &n)
	if rc != 0 {
		return nil, fmt.Errorf("this machine's key could not be read back (%d)", int(rc))
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
