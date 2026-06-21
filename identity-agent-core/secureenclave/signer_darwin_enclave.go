//go:build darwin && cgo && arm64

package secureenclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

static const UInt8 kAttestationKeyTag[] = "org.identitybot.attestation.v1";

static SecKeyRef se_findOrCreateKey(CFErrorRef *error) {
    CFDataRef tag = CFDataCreate(NULL, kAttestationKeyTag, sizeof(kAttestationKeyTag) - 1);
    if (!tag) return NULL;

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tag);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&key);
    CFRelease(query);
    CFRelease(tag);

    if (status == errSecSuccess && key != NULL) {
        return key;
    }

    CFMutableDictionaryRef privateAttrs = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef newTag = CFDataCreate(NULL, kAttestationKeyTag, sizeof(kAttestationKeyTag) - 1);
    CFDictionarySetValue(privateAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(privateAttrs, kSecAttrApplicationTag, newTag);

    CFMutableDictionaryRef params = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, CFSTR("256"));
    CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(params, kSecPrivateKeyAttrs, privateAttrs);

    key = SecKeyCreateRandomKey(params, error);
    CFRelease(params);
    CFRelease(privateAttrs);
    CFRelease(newTag);
    return key;
}

static int se_exportPublicKey(SecKeyRef privateKey, uint8_t *out, size_t outCap, size_t *outLen) {
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) return -1;

    CFErrorRef error = NULL;
    CFDataRef data = SecKeyCopyExternalRepresentation(publicKey, &error);
    CFRelease(publicKey);
    if (!data) {
        if (error) CFRelease(error);
        return -2;
    }

    const UInt8 *bytes = CFDataGetBytePtr(data);
    CFIndex len = CFDataGetLength(data);
    if ((size_t)len > outCap) {
        CFRelease(data);
        return -3;
    }
    for (CFIndex i = 0; i < len; i++) {
        out[i] = bytes[i];
    }
    *outLen = (size_t)len;
    CFRelease(data);
    return 0;
}

static int se_sign(SecKeyRef privateKey, const uint8_t *msg, size_t msgLen, uint8_t *out, size_t outCap, size_t *outLen) {
    CFDataRef message = CFDataCreate(NULL, msg, (CFIndex)msgLen);
    if (!message) return -1;

    CFErrorRef error = NULL;
    CFDataRef sig = SecKeyCreateSignature(privateKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, message, &error);
    CFRelease(message);
    if (!sig) {
        if (error) CFRelease(error);
        return -2;
    }

    const UInt8 *bytes = CFDataGetBytePtr(sig);
    CFIndex len = CFDataGetLength(sig);
    if ((size_t)len > outCap) {
        CFRelease(sig);
        return -3;
    }
    for (CFIndex i = 0; i < len; i++) {
        out[i] = bytes[i];
    }
    *outLen = (size_t)len;
    CFRelease(sig);
    return 0;
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

type darwinSecureEnclaveSigner struct {
	mu    sync.Mutex
	key   C.SecKeyRef
	ready bool
}

func newDarwinSecureEnclaveSigner() PlatformSigner {
	return &darwinSecureEnclaveSigner{}
}

func (s *darwinSecureEnclaveSigner) Available() bool {
	return s.ensureKey() == nil
}

func (s *darwinSecureEnclaveSigner) Platform() string { return "secure_enclave" }
func (s *darwinSecureEnclaveSigner) Label() string  { return "Apple Secure Enclave" }

func (s *darwinSecureEnclaveSigner) ensureKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready {
		return nil
	}
	var cErr C.CFErrorRef
	key := C.se_findOrCreateKey(&cErr)
	if key == 0 {
		return fmt.Errorf("secure enclave key unavailable")
	}
	s.key = key
	s.ready = true
	return nil
}

func (s *darwinSecureEnclaveSigner) PublicKey() ([]byte, error) {
	if err := s.ensureKey(); err != nil {
		return nil, err
	}
	buf := make([]byte, 256)
	var outLen C.size_t
	rc := C.se_exportPublicKey(s.key, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &outLen)
	if rc != 0 {
		return nil, fmt.Errorf("export secure enclave public key failed: %d", int(rc))
	}
	return buf[:int(outLen)], nil
}

func (s *darwinSecureEnclaveSigner) Sign(data []byte) ([]byte, error) {
	if err := s.ensureKey(); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	buf := make([]byte, 256)
	var outLen C.size_t
	rc := C.se_sign(
		s.key,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		&outLen,
	)
	if rc != 0 {
		return nil, fmt.Errorf("secure enclave sign failed: %d", int(rc))
	}
	return buf[:int(outLen)], nil
}