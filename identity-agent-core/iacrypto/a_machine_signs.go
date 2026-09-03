package iacrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// Everything about a machine's own key lives here, so the question "which
// algorithm is this" is answered once.
//
// It has to be asked at all because a machine's key is not an identity's key.
// People, organisations and instances are Ed25519. A machine is secp256r1,
// because that is the only thing a Secure Enclave, a Windows platform provider
// or a TPM will hold — and a key no hardware can hold is how three platforms
// ended up with signers that refuse.
//
// The danger of spreading that question around is specific and it has already
// happened once: the signing path encoded a machine's signature under the
// Ed25519 code because both signatures are 64 bytes, so nothing complained. A
// length check cannot catch that. Only asking one place what a key is can.

// aMachineKeyIsP256 reports whether these bytes are a secp256r1 point rather
// than an Ed25519 key.
//
// By length, because that is what actually distinguishes them: 33 compressed or
// 65 uncompressed for P-256, 32 for Ed25519. A machine's signer hands back
// whichever its hardware makes.
func aMachineKeyIsP256(pub []byte) bool {
	switch len(pub) {
	case 33:
		return pub[0] == 0x02 || pub[0] == 0x03
	case 65:
		return pub[0] == 0x04
	default:
		return false
	}
}

// MachineAIDForKey names a machine by whatever key its hardware gave it.
//
// The one place that decides. Callers pass the key and get the identifier; they
// do not choose a code, because choosing a code is the mistake.
func MachineAIDForKey(pub []byte) (string, error) {
	if aMachineKeyIsP256(pub) {
		return MachineAIDQB64(pub)
	}
	if len(pub) == ed25519.PublicKeySize {
		return MatterFixedQB64("B", pub)
	}
	return "", fmt.Errorf("a machine key is 32 bytes for Ed25519 or 33 or 65 for P-256, got %d", len(pub))
}

// MachineVerkeyForKey is the same key in verification-key form.
func MachineVerkeyForKey(pub []byte) (string, error) {
	if aMachineKeyIsP256(pub) {
		return MachineVerkeyQB64(pub)
	}
	if len(pub) == ed25519.PublicKeySize {
		return MatterFixedQB64("D", pub)
	}
	return "", fmt.Errorf("a machine key is 32 bytes for Ed25519 or 33 or 65 for P-256, got %d", len(pub))
}

// MachineSignatureQB64 encodes a signature under the code its key implies.
//
// BOTH SIGNATURES ARE 64 BYTES, which is why this exists as a function rather
// than a constant at each call site. A P-256 signature encoded under the Ed25519
// code is the right length, encodes without error, and claims to be something it
// is not — so the only defence is deciding from the key rather than from the
// signature.
func MachineSignatureQB64(pub, sig []byte) (string, error) {
	if aMachineKeyIsP256(pub) {
		return MatterFixedQB64(CodeP256Sig, sig)
	}
	return MatterFixedQB64("0B", sig)
}

// KeyFromMachineIdentifier recovers the key a machine identifier stands for,
// whichever kind it is.
//
// A machine's identifier IS its key, so this is what lets a grant be checked
// without asking anybody anything: the identifier decodes to the key, or it does
// not name that machine.
func KeyFromMachineIdentifier(aid string) ([]byte, error) {
	if len(aid) == 48 && len(aid) > 4 && aid[:4] == CodeP256N {
		return KeyFromMachineAID(aid)
	}
	return KeyFromNonTransferableAID(aid)
}

// VerifyMachineSignature checks a signature a machine made with its own key.
//
// Separate from the login package on purpose. That one verifies what people and
// organisations sign, and those are Ed25519 by design; teaching it about curves
// would put a machine's concerns inside identity verification, where a future
// reader would reasonably assume every key is an identity's.
func VerifyMachineSignature(verkeyQB64 string, sigQB64 string, message []byte) (bool, error) {
	pub, err := keyFromMachineVerkey(verkeyQB64)
	if err != nil {
		return false, err
	}

	if aMachineKeyIsP256(pub) {
		if len(sigQB64) != 88 || sigQB64[:2] != CodeP256Sig {
			return false, fmt.Errorf("a P-256 machine signature carries the %s code", CodeP256Sig)
		}
		sig, err := decodeTwoCharCode(sigQB64)
		if err != nil {
			return false, err
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), uncompressedP256(pub))
		if x == nil {
			return false, fmt.Errorf("the machine's key is not a point on P-256")
		}
		sum := sha256.Sum256(message)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, sum[:], r, s), nil
	}

	if len(sigQB64) != 88 || sigQB64[:2] != "0B" {
		return false, fmt.Errorf("an Ed25519 machine signature carries the 0B code")
	}
	sig, err := decodeTwoCharCode(sigQB64)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig), nil
}

func keyFromMachineVerkey(qb64 string) ([]byte, error) {
	if len(qb64) == 48 && qb64[:4] == CodeP256 {
		raw, err := KeyFromMachineAID(CodeP256N + qb64[4:])
		if err != nil {
			return nil, fmt.Errorf("the machine's key could not be read: %w", err)
		}
		return raw, nil
	}
	return KeyFromVerkeyQB64(qb64)
}

// decodeTwoCharCode recovers the raw bytes behind a two-character code.
//
// TWO lead bytes, not one. The count is (3 - size mod 3) mod 3, and a 64-byte
// signature is 1 mod 3, so encoding prepends two zero bytes and the code then
// replaces the two base64 characters they produced. Decoding has to restore both
// and drop both — assuming one leaves the whole value shifted by a byte, which
// is a signature that never verifies and no error to say why.
func decodeTwoCharCode(qb64 string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString("AA" + qb64[2:])
	if err != nil {
		return nil, fmt.Errorf("signature is not valid base64url: %w", err)
	}
	if len(raw) != 66 {
		return nil, fmt.Errorf("expected 64 signature bytes, got %d", len(raw)-2)
	}
	return raw[2:], nil
}

// uncompressedP256 returns the X9.63 form, decompressing when needed, because
// elliptic.Unmarshal only understands that one.
func uncompressedP256(pub []byte) []byte {
	if len(pub) == 65 {
		return pub
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pub)
	if x == nil {
		return nil
	}
	return elliptic.Marshal(elliptic.P256(), x, y)
}
