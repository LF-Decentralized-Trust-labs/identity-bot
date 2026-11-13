package secureenclave

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
)

// An Apple App Attest key signs only App Attest assertions.
//
// iOS and macOS do not let an App Attest key sign arbitrary bytes: the only
// thing it signs is generateAssertion(clientDataHash), and what it signs is not
// the bytes but a composite. So a statement that an App Attest key "signed" is,
// here, an assertion over the SHA-256 of the statement, and checking it is this
// file's job, not agentmessage.VerifyPerson's plain signature check.
//
// The assertion is CBOR {"signature": <ECDSA DER>, "authenticatorData": <37 bytes>}
// and, following Apple's published steps:
//
//  1. nonce = SHA-256(authenticatorData || clientDataHash)
//  2. the signature is the key's ECDSA-SHA-256 signature over nonce
//  3. authenticatorData[0:32] = SHA-256(appID), so it is the owner's app
//  4. authenticatorData[33:37] is the key's signature counter, big-endian
//
// The counter is returned and not judged here: the caller decides what a
// repeat means. The core's statements are one-use and expire in minutes, which
// is what stops a replayed assertion today.
//
// NOT PROVEN AGAINST A REAL DEVICE. The vector in apple_app_assertion_test.go
// is made by the same steps with a software key; no iPhone produced it.

// VerifyAppleAssertion checks that assertion is an App Attest assertion, by the
// key pub, for the app appID, over clientDataHash. It returns the counter.
func VerifyAppleAssertion(assertion, clientDataHash []byte, pub *ecdsa.PublicKey, appID string) (uint32, error) {
	if pub == nil || appID == "" || len(clientDataHash) != sha256.Size {
		return 0, notAttested("an assertion is checked for a key, an app and a SHA-256 client data hash")
	}
	top, err := cborDecodeAll(assertion)
	if err != nil {
		return 0, notAttested("the assertion is not valid CBOR: %v", err)
	}
	m, ok := top.(cborMap)
	if !ok {
		return 0, notAttested("the assertion is not a map")
	}
	sig, ok := m.text("signature").([]byte)
	if !ok || len(sig) == 0 {
		return 0, notAttested("the assertion has no signature")
	}
	authData, ok := m.text("authenticatorData").([]byte)
	if !ok || len(authData) < 37 {
		return 0, notAttested("the assertion's authenticator data is missing or too short")
	}
	rp := sha256.Sum256([]byte(appID))
	if !bytes.Equal(authData[:32], rp[:]) {
		return 0, notAttested("the assertion is for a different app")
	}
	nonce := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
	digest := sha256.Sum256(nonce[:])
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return 0, notAttested("the assertion's signature is not the key's")
	}
	return binary.BigEndian.Uint32(authData[33:37]), nil
}
