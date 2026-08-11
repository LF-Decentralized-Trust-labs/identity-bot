package iacrypto

import (
	"encoding/json"

	"encoding/base64"
	keri "github.com/grapeid/keri-go"
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
	nextVerkey, err := ed25519VerferQB64(nextPubRaw32)
	if err != nil {
		return nil, err
	}
	// The pre-rotation commitment is a digest of the next key's qb64 TEXT, not
	// of its raw bytes. Both are 32-byte Blake3 digests and both look correct;
	// only one is the value every other implementation computes when it
	// validates a rotation, and a commitment to the wrong representation makes
	// the identity unrotatable everywhere except here.
	nextDigest, err := keri.NextDigest(nextVerkey)
	if err != nil {
		return nil, err
	}

	// Built with keri-go rather than this package's own serialiser. Two KERI
	// implementations in one codebase is the arrangement keri-go exists to end:
	// an identifier is a digest of its own event, so a single byte of drift
	// produces an identity nobody recognises, and nothing fails until something
	// real is attempted.
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{verkey},
		NextDigests: []string{nextDigest},
		// This application's identities are self-addressing whatever the key
		// count, matching what the Python driver has always produced.
		Derivation: "self-addressing",
	})
	if err != nil {
		return nil, err
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	var event map[string]interface{}
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, err
	}

	return &Ed25519InceptionResult{
		AID:            ev.Identifier,
		SAID:           ev.SAID,
		InceptionEvent: event,
		RawBytesB64:    base64.StdEncoding.EncodeToString(raw),
		PublicKey:      verkey,
		NextKeyDigest:  nextDigest,
	}, nil
}
