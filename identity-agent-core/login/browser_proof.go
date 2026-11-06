package login

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

// A request made with a key a browser holds (ADR-066) proves it by a signature
// over the request, in this one form. The app's own back end and the Identity
// Agent that hosts the app check the same string, so it is written here once.

// BrowserProofLabel opens every proof, so a signature made for one purpose is
// not another's.
const BrowserProofLabel = "IABK2"

// Headers a request made with a browser key carries beside its session token.
const (
	HeaderBrowserProofTime  = "X-Browser-Proof-Time"
	HeaderBrowserProofNonce = "X-Browser-Proof-Nonce"
	HeaderBrowserProof      = "X-Browser-Proof"
)

// BrowserProofString is what a browser signs (ECDSA P-256 with SHA-256, the
// signature as WebCrypto gives it: r then s, 32 bytes each):
//
//	IABK2 \n METHOD \n HOST \n TARGET \n TIMESTAMP \n NONCE \n BINDING \n BODYHASH
//
// HOST is the request's host as sent (the Host header, port included), so a
// proof made for one Identity Agent is no proof at another. TARGET is the request's path and raw query as sent, BODYHASH the unpadded
// base64url SHA-256 of the body (of nothing, when there is none), so a request
// changed in flight no longer matches its proof. BINDING is the SHA-256 of the
// session token, unpadded base64url. HOST is lower-cased when signed. TIMESTAMP is RFC 3339 UTC.
func BrowserProofString(method, host, target, ts, nonce, binding string, body []byte) string {
	h := sha256.Sum256(body)
	return strings.Join([]string{BrowserProofLabel, method, strings.ToLower(host), target, ts, nonce, binding,
		base64.RawURLEncoding.EncodeToString(h[:])}, "\n")
}

// BrowserProofBodyHash is the last line of a proof string: the body's digest.
func BrowserProofBodyHash(body []byte) string {
	h := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BrowserSessionBinding is what a proof names the session by: the SHA-256 of
// its token, so the token itself is not in what is signed.
func BrowserSessionBinding(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BrowserKeyFromJWK reads a P-256 public key from its JWK coordinates, each
// exactly 32 bytes in one spelling and the point on the curve, and gives its
// RFC 7638 thumbprint.
func BrowserKeyFromJWK(x, y string) (*ecdsa.PublicKey, string, error) {
	tp, err := ThumbprintP256(x, y)
	if err != nil {
		return nil, "", err
	}
	xb, _ := base64.RawURLEncoding.DecodeString(x)
	yb, _ := base64.RawURLEncoding.DecodeString(y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, "", errors.New("the browser key is not a point on P-256")
	}
	return pub, tp, nil
}

// VerifyBrowserSignature checks sig (unpadded base64url, r then s) made over
// signed with pub.
func VerifyBrowserSignature(pub *ecdsa.PublicKey, signed, sig string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != 64 || pub == nil {
		return false
	}
	d := sha256.Sum256([]byte(signed))
	return ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}
