package didcomm

import (
	"crypto/ed25519"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"identity-agent-core/iacrypto"
)

// The two halves of a hybrid signature over a message that is not a JWM: the
// Ed25519 half is made by whoever builds the message (a KERI exchange message
// is signed as KERI signs it), and the ML-DSA half is made and checked here
// with the same messaging keys as every other signed message. Both must hold
// (verifyHybrid's rule: no classical-only fallback).

// SignPostQuantum is the ML-DSA-65 signature of this keyset's messaging key over
// msg. msg is what the caller's own domain tag has already been put in front of.
func (k *KeySet) SignPostQuantum(msg []byte) []byte {
	return mldsa65.Scheme().Sign(k.DsaPriv, msg, nil)
}

// EdPublicKey is the Ed25519 messaging key this DID names.
func (d *DID) EdPublicKey() (ed25519.PublicKey, error) {
	b, err := iacrypto.DecodeBase64URLSized(d.Ed, ed25519.PublicKeySize)
	if err != nil {
		return nil, errors.New("bad ed25519 key")
	}
	return ed25519.PublicKey(b), nil
}

// VerifyPostQuantum says whether sig is this DID's ML-DSA-65 signature over msg.
func (d *DID) VerifyPostQuantum(msg, sig []byte) bool {
	if len(sig) != iacrypto.MLDSA65SigBytes {
		return false
	}
	b, err := iacrypto.DecodeBase64URLSized(d.Dsa, iacrypto.MLDSA65VerkeyBytes)
	if err != nil {
		return false
	}
	pub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(b)
	if err != nil {
		return false
	}
	return mldsa65.Scheme().Verify(pub, msg, sig, nil)
}
