//go:build darwin && cgo && arm64

package secureenclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

// Dedicated Secure Enclave key for wrapping the root seed at rest. Deliberately a
// DIFFERENT key from the attestation key (signing and decryption never share a
// key). No user-presence requirement: the agent runs headless/always-on;
// per-action consent is the authorization layer's job, not storage's.
static const UInt8 kSeedWrapKeyTag[] = "org.identitybot.seedwrap.v1";

static SecKeyRef sw_findOrCreateKey(void) {
    CFDataRef tag = CFDataCreate(NULL, kSeedWrapKeyTag, sizeof(kSeedWrapKeyTag) - 1);
    if (!tag) return NULL;

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tag);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&key);
    CFRelease(query);

    if (status == errSecSuccess && key != NULL) {
        CFRelease(tag);
        return key;
    }

    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        NULL,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        NULL);
    if (!access) {
        CFRelease(tag);
        return NULL;
    }

    CFMutableDictionaryRef privateAttrs = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(privateAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(privateAttrs, kSecAttrApplicationTag, tag);
    CFDictionarySetValue(privateAttrs, kSecAttrAccessControl, access);

    CFMutableDictionaryRef params = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, CFSTR("256"));
    CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(params, kSecPrivateKeyAttrs, privateAttrs);

    CFErrorRef error = NULL;
    key = SecKeyCreateRandomKey(params, &error);
    if (error) CFRelease(error);
    CFRelease(params);
    CFRelease(privateAttrs);
    CFRelease(access);
    CFRelease(tag);
    return key;
}

// ECIES (P-256 + X9.63 KDF + AES-GCM) — Apple's standard hybrid encryption for
// SE-held EC keys: encrypt with the public half, decrypt inside the enclave.
static int sw_encrypt(SecKeyRef privateKey, const uint8_t *msg, size_t msgLen, uint8_t *out, size_t outCap, size_t *outLen) {
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) return -1;

    CFDataRef message = CFDataCreate(NULL, msg, (CFIndex)msgLen);
    if (!message) { CFRelease(publicKey); return -1; }

    CFErrorRef error = NULL;
    CFDataRef ct = SecKeyCreateEncryptedData(publicKey, kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, message, &error);
    CFRelease(message);
    CFRelease(publicKey);
    if (!ct) {
        if (error) CFRelease(error);
        return -2;
    }
    const UInt8 *bytes = CFDataGetBytePtr(ct);
    CFIndex len = CFDataGetLength(ct);
    if ((size_t)len > outCap) { CFRelease(ct); return -3; }
    for (CFIndex i = 0; i < len; i++) out[i] = bytes[i];
    *outLen = (size_t)len;
    CFRelease(ct);
    return 0;
}

static int sw_decrypt(SecKeyRef privateKey, const uint8_t *ct, size_t ctLen, uint8_t *out, size_t outCap, size_t *outLen) {
    CFDataRef data = CFDataCreate(NULL, ct, (CFIndex)ctLen);
    if (!data) return -1;

    CFErrorRef error = NULL;
    CFDataRef plain = SecKeyCreateDecryptedData(privateKey, kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, data, &error);
    CFRelease(data);
    if (!plain) {
        if (error) CFRelease(error);
        return -2;
    }
    const UInt8 *bytes = CFDataGetBytePtr(plain);
    CFIndex len = CFDataGetLength(plain);
    if ((size_t)len > outCap) { CFRelease(plain); return -3; }
    for (CFIndex i = 0; i < len; i++) out[i] = bytes[i];
    *outLen = (size_t)len;
    CFRelease(plain);
    return 0;
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

type darwinSeedWrapper struct {
	mu    sync.Mutex
	key   C.SecKeyRef
	ready bool
}

func newPlatformSeedWrapper() SeedWrapper {
	return &darwinSeedWrapper{}
}

func (w *darwinSeedWrapper) ensureKey() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ready {
		return nil
	}
	key := C.sw_findOrCreateKey()
	if key == 0 {
		return fmt.Errorf("secure enclave seed-wrap key unavailable")
	}
	w.key = key
	w.ready = true
	return nil
}

func (w *darwinSeedWrapper) Available() bool { return w.ensureKey() == nil }
func (w *darwinSeedWrapper) Scheme() string  { return "se-ecies-p256" }

func (w *darwinSeedWrapper) Wrap(plain []byte) ([]byte, error) {
	if err := w.ensureKey(); err != nil {
		return nil, err
	}
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty seed")
	}
	buf := make([]byte, 512)
	var outLen C.size_t
	rc := C.sw_encrypt(w.key,
		(*C.uint8_t)(unsafe.Pointer(&plain[0])), C.size_t(len(plain)),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &outLen)
	if rc != 0 {
		return nil, fmt.Errorf("secure enclave wrap failed: %d", int(rc))
	}
	return buf[:int(outLen)], nil
}

func (w *darwinSeedWrapper) Unwrap(blob []byte) ([]byte, error) {
	if err := w.ensureKey(); err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty blob")
	}
	buf := make([]byte, 512)
	var outLen C.size_t
	rc := C.sw_decrypt(w.key,
		(*C.uint8_t)(unsafe.Pointer(&blob[0])), C.size_t(len(blob)),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &outLen)
	if rc != 0 {
		return nil, fmt.Errorf("secure enclave unwrap failed: %d", int(rc))
	}
	return buf[:int(outLen)], nil
}
