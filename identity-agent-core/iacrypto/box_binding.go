package iacrypto

import (
	"encoding/base64"
	"fmt"

	"github.com/zeebo/blake3"
)

// What the hardware is asked to vouch for.
//
// An attestation report can cover one value of the caller's choosing, and which
// value it is decides what the report is worth.
//
// It used to be the fingerprint of the certificate on the connection, which
// proved the sealed machine held the key for THIS connection and so could not
// have a genuine report replayed onto a connection somebody else terminated.
// That is the right property and it is unobtainable here: a proxy in front of
// the machine terminates the connection by design, so the certificate a client
// sees is the proxy's and the fingerprints cannot match. The check failed
// exactly where it was needed, and correctly — from the client's side that
// situation is indistinguishable from interception.
//
// So the report covers the machine's encryption keys instead. Then it says:
// the private half of these keys is inside this sealed machine. A proxy can
// terminate the connection, read the headers and route the traffic, and it
// still cannot produce that statement, because it cannot make the hardware sign
// one and it does not hold the key. The client encrypts to the keys the report
// covers, and what is inside is beyond the proxy whether or not it terminates
// anything.
//
// The keys are public — they are in the identifier's own inception event — so
// binding them reveals nothing a verifier does not already have.

// BoxKeyBinding is the value a sealed machine asks its hardware to cover.
//
// Both keys, in a fixed order, each preceded by its length, after a label. The
// same reasoning as anywhere else two implementations must agree on bytes: a
// delimiter only separates fields that cannot contain it, and lengths cannot be
// confused for content.
//
// Returned as text because that is what the hardware call takes, and the caller
// should not be reformatting it on the way.
func BoxKeyBinding(x25519, mlkem768 []byte) (string, error) {
	if len(x25519) != X25519PubkeyBytes {
		return "", fmt.Errorf("expected a %d-byte agreement key, got %d", X25519PubkeyBytes, len(x25519))
	}
	if len(mlkem768) != MLKEM768EncapBytes {
		return "", fmt.Errorf("expected a %d-byte encapsulation key, got %d", MLKEM768EncapBytes, len(mlkem768))
	}

	h := blake3.New()
	_, _ = h.Write([]byte("IA-BOX-KEYS-V1"))
	for _, k := range [][]byte{x25519, mlkem768} {
		var n [4]byte
		n[0] = byte(len(k) >> 24)
		n[1] = byte(len(k) >> 16)
		n[2] = byte(len(k) >> 8)
		n[3] = byte(len(k))
		_, _ = h.Write(n[:])
		_, _ = h.Write(k)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// BoxKeyBindingForEvent is the same value, computed from what an identifier
// committed to rather than from keys handed over separately.
//
// This is the form a verifier wants. Taking the keys from the event means the
// value being compared against the report is derived from the identifier
// itself, so there is no step where a different set of keys could be
// substituted between reading the identity and checking the hardware.
func BoxKeyBindingForEvent(event map[string]interface{}) (string, error) {
	x, kem, err := AnchoredAgreementKeys(event)
	if err != nil {
		return "", err
	}
	return BoxKeyBinding(x, kem)
}

// PairingOfferBinding is what a machine's hardware vouches for while it is
// being adopted.
//
// Adoption is earlier than everything else: the machine has no identity yet,
// so it has no anchored encryption keys to bind. What it does have, and what
// the owner is about to sign a delegation over, is the signing key material it
// just generated. That is the substitution that matters at this step — swap
// those keys and the delegation the owner issues covers somebody else's
// machine, permanently, in a log third parties read and find correct.
//
// So the report covers exactly the two keys being offered, and the owner
// recomputes this from what arrived before signing anything.
func PairingOfferBinding(publicKey, nextPublicKey string) (string, error) {
	if publicKey == "" || nextPublicKey == "" {
		return "", fmt.Errorf("an offer must carry both a key and its successor")
	}
	h := blake3.New()
	_, _ = h.Write([]byte("IA-BOX-OFFER-V1"))
	for _, k := range []string{publicKey, nextPublicKey} {
		var n [4]byte
		n[0] = byte(len(k) >> 24)
		n[1] = byte(len(k) >> 16)
		n[2] = byte(len(k) >> 8)
		n[3] = byte(len(k))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(k))
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
