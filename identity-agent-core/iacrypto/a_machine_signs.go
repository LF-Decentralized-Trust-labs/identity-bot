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
// THE LINE IS NOT MACHINE VERSUS PERSON, and stating it that way is a trap.
//
// "Machines are secp256r1, people are Ed25519" reads well and will be
// implemented literally — and the sealed box that HOLDS an identity is a
// machine, as is a phone. Someone will read that sentence and put an identity
// key on P-256 inside an attested guest.
//
// The actual invariant: a key a chip holds on a machine's behalf uses the curve
// that chip can sign with, which is secp256r1 on every secure element that
// exists. A KERI identity prefix stays Ed25519 wherever it lives, including on
// machines. This file is only ever about the first kind.
//
// And the reason is non-extractability, not that an API lacks Ed25519. A seed
// sealed to a TPM and unwrapped into memory would keep one curve and give up the
// property worth having: same-user code can USE a hardware key, and cannot carry
// it to another machine. A software key loses that.
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
		// NORMALISED HERE, because the hardware does not do it.
		//
		// ECDSA admits two valid signatures per message — (r, s) and (r, n-s) —
		// and MEASURED: Apple's Secure Enclave emits either. Left alone, one
		// request has two signature strings, and a request is remembered by its
		// signature so it cannot be replayed; the second string would spend it
		// again.
		//
		// So the canonical low form is chosen at the moment of encoding, which is
		// the one place every machine signature passes through, and the verifier
		// then requires it. Normalising does not invalidate the signature: both
		// forms verify, and this picks the one that is a stable name for itself.
		return MatterFixedQB64(CodeP256Sig, canonicalP256Signature(sig))
	}
	return MatterFixedQB64("0B", sig)
}

// canonicalP256Signature returns the low-s form of a 64-byte r||s signature.
//
// Anything that is not 64 bytes is handed back untouched, so the length check in
// MatterFixedQB64 reports it rather than this quietly reshaping a value it does
// not understand.
func canonicalP256Signature(sig []byte) []byte {
	if len(sig) != 64 {
		return sig
	}
	s := new(big.Int).SetBytes(sig[32:])
	if !isHighS(s) {
		return sig
	}
	low := new(big.Int).Sub(elliptic.P256().Params().N, s)
	out := make([]byte, 64)
	copy(out[:32], sig[:32])
	low.FillBytes(out[32:])
	return out
}

// KeyFromMachineIdentifier recovers the key a machine identifier stands for,
// whichever kind it is.
//
// A machine's identifier IS its key, so this is what lets a grant be checked
// without asking anybody anything: the identifier decodes to the key, or it does
// not name that machine.
func KeyFromMachineIdentifier(aid string) ([]byte, error) {
	if len(aid) == 48 && aid[:4] == CodeP256N {
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

		// ONLY THE LOW-S FORM IS ACCEPTED, and this is not fastidiousness.
		//
		// ECDSA verifies both (r, s) and (r, n-s) — two different signatures over
		// one message, either valid. Ed25519 has no such property, so nothing
		// upstream was built expecting it, and one thing upstream depends on its
		// absence: a signed request is remembered by its signature string so it
		// cannot be replayed. Under ECDSA anybody who observes a request inside
		// the freshness window can negate s, produce a second string that
		// verifies the same bytes, and spend the request again.
		//
		// So the malleable half is refused here rather than defended against
		// everywhere it could be replayed. The hardware does NOT produce the low
		// form on its own — Apple's Secure Enclave emits either, measured — so
		// MachineSignatureQB64 normalises at the moment of encoding and this
		// requires what that produced.
		if isHighS(s) {
			return false, fmt.Errorf("this signature is in the malleable form; only the " +
				"canonical low-s form is accepted, because a request is remembered by " +
				"its signature and the other form would spend it twice")
		}
		if r.Sign() <= 0 || s.Sign() <= 0 {
			return false, fmt.Errorf("a signature component is zero, which is not a signature")
		}
		return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, sum[:], r, s), nil
	}

	// Checked before the call, because ed25519.Verify PANICS on a key of the
	// wrong length rather than returning false. Anything reaching here that is
	// not an Ed25519 key is a value that classified as neither, and the honest
	// answer is to say so.
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("that is not a key this machine could have signed with: "+
			"%d bytes is neither an Ed25519 key nor a P-256 point", len(pub))
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

// KeyFromMachineVerkey recovers the key behind a machine's published
// verification key, whichever kind it is.
//
// Exported because a grant records the identifier AND the key and has to compare
// them, and comparing them means decoding both by the same rules. Decoding one
// with Ed25519 rules and the other with the machine's is how a grant refuses a
// key that is perfectly correct.
func KeyFromMachineVerkey(qb64 string) ([]byte, error) { return keyFromMachineVerkey(qb64) }

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

// isHighS reports whether s is above half the curve order.
//
// The negation of any valid s is also valid, so exactly one of the pair is below
// the halfway point. Taking the low one as canonical is the ordinary convention
// and it is what makes a signature a stable name for itself.
func isHighS(s *big.Int) bool {
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	return s.Cmp(half) > 0
}
