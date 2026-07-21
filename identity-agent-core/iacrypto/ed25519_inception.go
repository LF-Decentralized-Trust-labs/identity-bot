package iacrypto

import (
	"encoding/base64"
)

// Ed25519InceptionResult mirrors the keripy driver response shape for a plain
// (single-sig ed25519) inception.
type Ed25519InceptionResult struct {
	AID            string                 `json:"aid"`
	SAID           string                 `json:"said"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	RawBytesB64    string                 `json:"raw_bytes_b64"`
	PublicKey      string                 `json:"public_key"`      // CESR verkey (D…)
	NextKeyDigest  string                 `json:"next_key_digest"` // Blake3 QB64 (E…)
}

// BuildEd25519Inception builds a REAL plain KERI icp for a single ed25519 key
// with one pre-rotated next key, using the same keri-1.1.17 SerderKERI makify
// (dummy d/i → Blake3 → self-addressing AID) as the hybrid builder. This is the
// keri-go native mint used where the Python driver isn't available (mobile) —
// the "bridge/native on mobile, driver on desktop" architecture, not a
// fabricated identifier.
func BuildEd25519Inception(pubRaw32, nextPubRaw32 []byte) (*Ed25519InceptionResult, error) {
	verkey, err := ed25519VerferQB64(pubRaw32)
	if err != nil {
		return nil, err
	}
	nextDigest, err := Blake3QB64(nextPubRaw32)
	if err != nil {
		return nil, err
	}

	w := icpWire{
		T:  "icp",
		S:  "0",
		Kt: "1",
		K:  []string{verkey},
		Nt: "1",
		N:  []string{nextDigest},
		Bt: "0",
		B:  []interface{}{},
		C:  []interface{}{},
		A:  []anchorSeal{},
	}
	final, raw, err := makifyICPWire(w)
	if err != nil {
		return nil, err
	}
	return &Ed25519InceptionResult{
		AID:            final.I,
		SAID:           final.D,
		InceptionEvent: wireToInceptionMap(final),
		RawBytesB64:    base64.StdEncoding.EncodeToString(raw),
		PublicKey:      verkey,
		NextKeyDigest:  nextDigest,
	}, nil
}
