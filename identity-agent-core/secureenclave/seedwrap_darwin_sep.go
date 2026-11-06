//go:build darwin && cgo && sepblob && !ios

package secureenclave

/*
#cgo LDFLAGS: -lsep -framework CryptoKit -framework Foundation -L/usr/lib/swift -lswiftCore
#include <stddef.h>
int sep_available(void);
int sepw_wrap(const unsigned char *plain, size_t plen, unsigned char *out, size_t cap, size_t *n);
int sepw_unwrap(const unsigned char *blob, size_t blen, unsigned char *out, size_t cap, size_t *n);
*/
import "C"

import (
	"bytes"
	"fmt"
	"sync"
	"unsafe"
)

// The macOS seed wrapper: the Secure Enclave, without the keychain.
//
// An enclave key is never stored in the enclave; the enclave wraps it and
// returns a blob only that chip can unwrap. The older wrapper asked the keychain
// to hold the key, which needs an entitlement a bare helper cannot have, so it
// could never persist anything. This one makes a key per wrap and keeps the
// key's blob inside the wrapped seed itself (sepw_wrap in sep/sep.swift). It
// needs no entitlement, profile or bundle, and works on any Mac with a Secure
// Enclave: Apple silicon, and Intel Macs with a T2. On a Mac with neither,
// sep_available is 0 and the seed is reported unwrapped, not wrapped.
//
// What it does not give: the wrapped seed can be opened by anything running as
// this person on this Mac, since a file at 0600 has no per-application gate.
// The seed cannot be copied to another machine and opened; its use can be
// borrowed locally. Same property, same wording, as the signer next door.
//
// Built behind the sepblob tag with the Swift shim (scripts/build-sep-shim.sh),
// like the signer. Without the tag the build has no macOS wrapper and says so.
type sepSeedWrapper struct {
	once   sync.Once
	proved bool
}

func newPlatformSeedWrapper() SeedWrapper { return &sepSeedWrapper{} }

// SeedWrapScheme recorded in the envelope.
const sepSeedScheme = "se-ecdh-p256-aes256gcm"

func (w *sepSeedWrapper) Scheme() string { return sepSeedScheme }

// Available is PROVEN, not inferred from the device reporting an enclave: a
// seed is wrapped and opened once, and only a round trip makes this true.
func (w *sepSeedWrapper) Available() bool {
	w.once.Do(func() {
		if C.sep_available() != 1 {
			return
		}
		probe := bytes.Repeat([]byte{0x5a}, 32)
		blob, err := w.Wrap(probe)
		if err != nil {
			return
		}
		back, err := w.Unwrap(blob)
		w.proved = err == nil && bytes.Equal(back, probe)
	})
	return w.proved
}

func (w *sepSeedWrapper) Wrap(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty seed")
	}
	buf := make([]byte, 1024)
	var n C.size_t
	if rc := C.sepw_wrap((*C.uchar)(unsafe.Pointer(&plain[0])), C.size_t(len(plain)),
		(*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &n); rc != 0 {
		return nil, fmt.Errorf("secure enclave wrap failed: %d", int(rc))
	}
	return buf[:int(n)], nil
}

func (w *sepSeedWrapper) Unwrap(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty blob")
	}
	buf := make([]byte, 256)
	var n C.size_t
	if rc := C.sepw_unwrap((*C.uchar)(unsafe.Pointer(&blob[0])), C.size_t(len(blob)),
		(*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &n); rc != 0 {
		return nil, fmt.Errorf("secure enclave unwrap failed: %d", int(rc))
	}
	return buf[:int(n)], nil
}
