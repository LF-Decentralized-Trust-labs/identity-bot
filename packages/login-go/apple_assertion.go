package login

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// An installed front end on Apple's platforms proves each call with an App Attest
// assertion, not a plain signature.
//
// An App Attest key signs only generateAssertion(clientDataHash), so the proof a
// call carries (IABK1, ADR-072 Amendment 4) is, for such a key, an assertion over
// the SHA-256 of the same proof text, in `x-browser-proof` as unpadded base64url. A
// plain proof is 64 bytes (r then s); an assertion is longer, which is how a back end
// tells them apart (IsAssertionProof). Checking it is the Identity Agent's own
// `VerifyAppleAssertion` (identity-agent-core/secureenclave), whose steps these are,
// and its vector is held in ../login-web/test-vectors/installed-app.json.
//
// NOT PROVEN AGAINST A REAL DEVICE: the vector is made by Apple's published steps
// with a software key; no iPhone or Mac produced it.

// IsAssertionProof is whether a decoded `x-browser-proof` is an App Attest
// assertion rather than a 64-byte plain signature.
func IsAssertionProof(raw []byte) bool { return len(raw) > 64 }

// VerifyAppleAssertion checks that assertion is an App Attest assertion by the key
// pub, for the program appID ("<team id>.<bundle id>"), over clientDataHash (the
// SHA-256 of the proof text). It gives the key's signature counter, which it does not
// judge: a repeat is for the caller to decide.
func VerifyAppleAssertion(assertion, clientDataHash []byte, pub *ecdsa.PublicKey, appID string) (uint32, error) {
	if pub == nil || appID == "" || len(clientDataHash) != sha256.Size {
		return 0, errors.New("login: an assertion is checked for a key, a program and a SHA-256 client data hash")
	}
	sig, authData, err := readAssertion(assertion)
	if err != nil {
		return 0, err
	}
	if len(authData) < 37 {
		return 0, errors.New("login: the assertion's authenticator data is too short")
	}
	rp := sha256.Sum256([]byte(appID))
	if !bytes.Equal(authData[:32], rp[:]) {
		return 0, errors.New("login: the assertion is for a different program")
	}
	nonce := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
	digest := sha256.Sum256(nonce[:])
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return 0, errors.New("login: the assertion's signature is not the key's")
	}
	return binary.BigEndian.Uint32(authData[33:37]), nil
}

// readAssertion reads {"signature": bytes, "authenticatorData": bytes}, the only
// shape an assertion has, as CBOR: a map of two text keys to byte strings, in
// either order, with the shortest encoding of every length and nothing after.
func readAssertion(b []byte) (sig, authData []byte, err error) {
	bad := errors.New("login: the assertion is not the CBOR map an App Attest assertion is")
	if len(b) == 0 || b[0] != 0xa2 {
		return nil, nil, bad
	}
	b = b[1:]
	head := func(major byte) (int, bool) {
		if len(b) == 0 || b[0]>>5 != major {
			return 0, false
		}
		info := b[0] & 0x1f
		b = b[1:]
		switch {
		case info < 24:
			return int(info), true
		case info == 24 && len(b) >= 1 && b[0] >= 24:
			n := int(b[0])
			b = b[1:]
			return n, true
		case info == 25 && len(b) >= 2 && binary.BigEndian.Uint16(b) >= 256:
			n := int(binary.BigEndian.Uint16(b))
			b = b[2:]
			return n, true
		}
		return 0, false
	}
	take := func(major byte) ([]byte, bool) {
		n, ok := head(major)
		if !ok || n > len(b) {
			return nil, false
		}
		v := b[:n]
		b = b[n:]
		return v, true
	}
	for i := 0; i < 2; i++ {
		k, ok := take(3)
		if !ok {
			return nil, nil, bad
		}
		v, ok := take(2)
		if !ok {
			return nil, nil, bad
		}
		switch string(k) {
		case "signature":
			if sig != nil {
				return nil, nil, bad
			}
			sig = append([]byte{}, v...)
		case "authenticatorData":
			if authData != nil {
				return nil, nil, bad
			}
			authData = append([]byte{}, v...)
		default:
			return nil, nil, bad
		}
	}
	if len(b) != 0 || len(sig) == 0 || authData == nil {
		return nil, nil, bad
	}
	return sig, authData, nil
}
