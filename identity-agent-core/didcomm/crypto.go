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

// blake3Body is the protocol-wide content hash for the JWM body.
func blake3Body(b []byte) string {
	s := blake3.Sum256(b)
	return "E" + b64.EncodeToString(s[:]) // CESR-style E prefix (canonical byte-freeze pending)
}
