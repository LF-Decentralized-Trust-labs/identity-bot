package didcomm

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"identity-agent-core/iacrypto"
)

// Hybrid authcrypt: the content key is derived from BOTH an X25519 ECDH-1PU exchange
// (ephemeral-static Ze for freshness + static-static Zs for sender authentication) AND
// an ML-KEM-768 encapsulation, combined via HKDF — both must succeed to decrypt.
// Content encryption is XChaCha20-Poly1305.

// kaMaterial is the sender's per-message key-agreement material carried in the JWE
// `apu` header: the ephemeral X25519 public key and the ML-KEM-768 ciphertext.
type kaMaterial struct {
	EphemeralX string `json:"epk"`    // base64url ephemeral X25519 public key
	KemCT      string `json:"kem_ct"` // base64url ML-KEM-768 ciphertext
}

func deriveContentKey(ze, zs, ssKEM []byte, skid, kid string) ([]byte, error) {
	ikm := make([]byte, 0, len(ze)+len(zs)+len(ssKEM))
	ikm = append(ikm, ze...)
	ikm = append(ikm, zs...)
	ikm = append(ikm, ssKEM...)
	info := []byte(CipherSuite + "|authcrypt|" + skid + "|" + kid)
	r := hkdf.New(sha256.New, ikm, nil, info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// authEncrypt encrypts plaintext to rcpt, authenticated as sender. Returns the `apu`
// material (base64url), the nonce, and the ciphertext (incl. AEAD tag).
func authEncrypt(sender *KeySet, rcpt *parsedDID, plaintext, aad []byte) (apu string, nonce, ct []byte, err error) {
	var epkPriv [32]byte
	if _, err = rand.Read(epkPriv[:]); err != nil {
		return "", nil, nil, err
	}
	epkPub, err := curve25519.X25519(epkPriv[:], curve25519.Basepoint)
	if err != nil {
		return "", nil, nil, err
	}
	ze, err := curve25519.X25519(epkPriv[:], rcpt.x25519[:])
	if err != nil {
		return "", nil, nil, err
	}
	zs, err := curve25519.X25519(sender.XPriv[:], rcpt.x25519[:])
	if err != nil {
		return "", nil, nil, err
	}
	kemCT, ssKEM, err := mlkem768.Scheme().Encapsulate(rcpt.kem)
	if err != nil {
		return "", nil, nil, fmt.Errorf("mlkem encapsulate: %w", err)
	}
	key, err := deriveContentKey(ze, zs, ssKEM, sender.AID, rcpt.aid)
	if err != nil {
		return "", nil, nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", nil, nil, err
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err = rand.Read(nonce); err != nil {
		return "", nil, nil, err
	}
	ct = aead.Seal(nil, nonce, plaintext, aad)
	kmB, _ := json.Marshal(kaMaterial{EphemeralX: b64.EncodeToString(epkPub), KemCT: b64.EncodeToString(kemCT)})
	return b64.EncodeToString(kmB), nonce, ct, nil
}

// authDecrypt reverses authEncrypt. Either key-agreement half failing rejects the
// message (key_agreement_failed).
func authDecrypt(rcpt *KeySet, sender *parsedDID, apu string, nonce, ct, aad []byte) ([]byte, error) {
	kmB, err := b64.DecodeString(apu)
	if err != nil {
		return nil, fmt.Errorf("key_agreement_failed: bad apu")
	}
	var km kaMaterial
	if err := json.Unmarshal(kmB, &km); err != nil {
		return nil, fmt.Errorf("key_agreement_failed: bad apu json")
	}
	epkPub, err := b64.DecodeString(km.EphemeralX)
	if err != nil || len(epkPub) != 32 {
		return nil, fmt.Errorf("key_agreement_failed: bad epk")
	}
	kemCT, err := b64.DecodeString(km.KemCT)
	if err != nil {
		return nil, fmt.Errorf("key_agreement_failed: bad kem ct")
	}
	ze, err := curve25519.X25519(rcpt.XPriv[:], epkPub)
	if err != nil {
		return nil, fmt.Errorf("key_agreement_failed: %w", err)
	}
	zs, err := curve25519.X25519(rcpt.XPriv[:], sender.x25519[:])
	if err != nil {
		return nil, fmt.Errorf("key_agreement_failed: %w", err)
	}
	ssKEM, err := mlkem768.Scheme().Decapsulate(rcpt.KemPriv, kemCT)
	if err != nil {
		return nil, fmt.Errorf("key_agreement_failed: mlkem decapsulate: %w", err)
	}
	key, err := deriveContentKey(ze, zs, ssKEM, sender.aid, rcpt.AID)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("key_agreement_failed: aead open: %w", err)
	}
	return pt, nil
}

// signHybrid produces the Ed25519 + ML-DSA-65 dual signature over msg.
func signHybrid(k *KeySet, msg []byte) (edSig, dsaSig []byte) {
	edSig = ed25519.Sign(k.EdPriv, msg)
	dsaSig = mldsa65.Scheme().Sign(k.DsaPriv, msg, nil)
	return
}

// verifyHybrid requires BOTH signatures to verify (E-4: no classical-only fallback).
func verifyHybrid(sender *parsedDID, msg, edSig, dsaSig []byte) bool {
	if !ed25519.Verify(sender.ed, msg, edSig) {
		return false
	}
	return mldsa65.Scheme().Verify(sender.dsa, msg, dsaSig, nil)
}

// The body_hash a signed message carries comes in two forms, and both are
// read (bodyHashes). Which one is written is a separate decision, made here.
//
// writeCESRBodyHash switches writing from the earlier form to the CESR
// digest. It stays off until every reader in use accepts both forms: a reader
// that accepts only the earlier form refuses every message written in the
// CESR one, and an Identity Agent and the machines that deliver to it do not
// upgrade at the same moment. Turning it on is the whole of the switch.
const writeCESRBodyHash = false

// writtenBodyHash is the body_hash a new signed message is written with.
func writtenBodyHash(b []byte) string {
	if writeCESRBodyHash {
		return cesrBodyHash(b)
	}
	return bodyHashBeforeCESR(b)
}

// cesrBodyHash is the Blake3-256 digest of the body as a CESR digest in qb64
// (code E), the form every other digest in the protocol takes, so another
// implementation reading a value that starts with E reads it as what it is.
func cesrBodyHash(b []byte) string {
	return iacrypto.Blake3QB64Must(b)
}

// bodyHashBeforeCESR is E followed by the raw Blake3-256 digest of the body in
// unpadded base64url: the form messages have been written with. It looks like
// a CESR digest and is not one, which is why writing moves to cesrBodyHash.
func bodyHashBeforeCESR(b []byte) string {
	sum := blake3.Sum256(b)
	return "E" + b64.EncodeToString(sum[:])
}

// bodyHashes are the body_hash values a body may be signed under, CESR first.
// Both are read, permanently: a message, a countersigned conversation or a
// kept proof signed under either form verifies.
//
// Reading both gives no value a second accepted spelling, which ADR-060
// forbids. Each is a function of the body, never a free choice: a signed
// plaintext carries no body_hash at all, and both are derived from the body
// it carries; a kept signed message carries one, and it is accepted only if
// it is exactly one of the two derived from its body, and only under a
// signature that covers it. So a message signed under one form cannot be
// respelled into the other without the sender's key, and nothing compared as
// text (a body, a signature, an entry's hash) can be given a second string.
func bodyHashes(b []byte) [2]string {
	return [2]string{cesrBodyHash(b), bodyHashBeforeCESR(b)}
}
