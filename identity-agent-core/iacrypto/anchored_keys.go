package iacrypto

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// Reading the encryption keys back out of an identifier's inception event.
//
// The inception event can carry the key-agreement keys in its anchor, and it has
// been able to since that format was frozen. Nothing ever read them back. They
// were written, the identifier committed to them, and every part of the system
// that needed to know which keys belonged to an identifier asked the network
// instead — which is a question the network is free to answer wrongly.
//
// This is the half that makes the anchor mean something. An identifier is
// derived from its inception event, so a key inside that event is committed to
// by the identifier itself: changing the key changes the event, which changes
// the identifier. There is nothing to intercept, because there is nothing to
// fetch.

// KeySetAnchor builds the seal an inception event carries so that the
// identifier commits to the keys an identity is reached and authenticated on.
//
// This is the half that had never been written. The reader below has always
// been able to find these keys; nothing put them there, so every identifier in
// existence answered "not anchored" and every counterparty had to fetch the
// keys from the agent and take its word for them.
//
// All four, not the agreement pair alone. Committing only the keys used to
// encrypt leaves the keys used to SIGN uncommitted, which means a counterparty
// can be handed a set where the confidentiality half belongs to the identifier
// and the authenticity half belongs to somebody else. Nothing in the envelope
// as it stands can be forged that way, because sender authentication rests on
// the agreement key — but "safe given how it is used today" is a property of
// the current caller rather than of the commitment, and the cost of committing
// all four is nothing while an identity is being founded and a migration
// afterwards.
//
// Two lists rather than one, because they answer different questions: `ka` is
// what to encrypt to, `sa` is what verifies a signature. Order within each is
// fixed — classical first, post-quantum second — and each key carries its own
// type code, so a reader that checks the code catches a swapped pair rather
// than decoding one as the other.
func KeySetAnchor(x25519, mlkem768, ed25519Pub, mldsa65Pub []byte) (map[string]interface{}, error) {
	x, err := EncodeLargeFixed(CESRX25519Pubkey, x25519, X25519PubkeyBytes)
	if err != nil {
		return nil, fmt.Errorf("agreement key: %w", err)
	}
	k, err := EncodeLargeFixed(CESRMLKEM768Encap, mlkem768, MLKEM768EncapBytes)
	if err != nil {
		return nil, fmt.Errorf("encapsulation key: %w", err)
	}
	ed := VerkeyQB64(ed25519Pub)
	if ed == "" || len(ed25519Pub) != Ed25519PubkeyBytes {
		return nil, fmt.Errorf("expected a %d-byte signing key, got %d", Ed25519PubkeyBytes, len(ed25519Pub))
	}
	dsa, err := EncodeLargeFixed(CESRMLDSA65Verkey, mldsa65Pub, MLDSA65VerkeyBytes)
	if err != nil {
		return nil, fmt.Errorf("post-quantum signing key: %w", err)
	}
	return map[string]interface{}{
		"ia": CipherSuiteIAHybrid1,
		"ka": []string{x, k},
		"sa": []string{ed, dsa},
	}, nil
}

// AnchoredSigningKeys returns the signature keys an inception event commits to.
//
// ErrNotAnchored when the seal predates them, which is distinct from a seal
// that has them and will not parse.
func AnchoredSigningKeys(event map[string]interface{}) (ed25519Pub, mldsa65Pub []byte, err error) {
	for _, seal := range anchorList(event["a"]) {
		if suite, _ := seal["ia"].(string); suite != CipherSuiteIAHybrid1 {
			continue
		}
		sa := keyList(seal["sa"])
		if len(sa) == 0 {
			return nil, nil, ErrNotAnchored
		}
		if len(sa) != 2 {
			return nil, nil, fmt.Errorf("the signing-key anchor should hold exactly two keys, found %d", len(sa))
		}
		ed, derr := KeyFromVerkeyQB64(sa[0])
		if derr != nil {
			return nil, nil, fmt.Errorf("the anchored signing key is unusable: %w", derr)
		}
		dsa, derr := DecodeLargeFixed(CESRMLDSA65Verkey, sa[1], MLDSA65VerkeyBytes)
		if derr != nil {
			return nil, nil, fmt.Errorf("the anchored post-quantum signing key is unusable: %w", derr)
		}
		return ed, dsa, nil
	}
	return nil, nil, ErrNotAnchored
}

// ErrNotAnchored means the event carries no key-agreement anchor.
//
// Distinguished from a malformed one because the two have different causes: an
// identifier created before the anchor existed has none, while an identifier
// that has one that will not parse is either corrupt or being tampered with.
// Both refuse — the difference is for the person reading the logs, not for the
// decision.
var ErrNotAnchored = errors.New("this identifier does not commit to any encryption keys")

// DecodeLargeFixed is the inverse of EncodeLargeFixed.
//
// The code is checked rather than skipped. Two different key types are stored in
// the same list and are the same shape once the prefix is removed, so decoding
// whichever one is at a given position without checking what it claims to be is
// how an encapsulation key gets read as an agreement key.
func DecodeLargeFixed(code, qb64 string, expectedLen int) ([]byte, error) {
	if len(code) != 4 {
		return nil, fmt.Errorf("provisional CESR code must be 4 chars, got %q", code)
	}
	if len(qb64) < 4 || qb64[:4] != code {
		return nil, fmt.Errorf("expected a %s value, got one starting %.4q", code, qb64)
	}
	raw, err := base64.RawURLEncoding.DecodeString(qb64[4:])
	if err != nil {
		return nil, fmt.Errorf("%s value is not valid base64url: %w", code, err)
	}
	if expectedLen > 0 && len(raw) != expectedLen {
		return nil, fmt.Errorf("expected %d bytes for %s, got %d", expectedLen, code, len(raw))
	}
	return raw, nil
}

// AnchoredAgreementKeys returns the key-agreement keys an inception event
// commits to.
//
// Both keys or neither. The envelope needs the pair — one classical and one
// post-quantum, combined — so an event carrying only one of them is not a
// weaker version of this, it is unusable, and returning a partial answer would
// let a caller proceed with half the protection it asked for.
func AnchoredAgreementKeys(event map[string]interface{}) (x25519, mlkem768 []byte, err error) {
	anchors := anchorList(event["a"])
	if len(anchors) == 0 {
		return nil, nil, ErrNotAnchored
	}

	for _, seal := range anchors {
		if suite, _ := seal["ia"].(string); suite != CipherSuiteIAHybrid1 {
			// Some other kind of seal. An anchor list is general and carries
			// whatever an identifier needed to commit to; ours is the one
			// labelled with the suite it belongs to.
			continue
		}

		ka := keyList(seal["ka"])
		if len(ka) != 2 {
			return nil, nil, fmt.Errorf("the encryption-key anchor should hold exactly two keys, found %d", len(ka))
		}
		first, second := ka[0], ka[1]

		x, err := DecodeLargeFixed(CESRX25519Pubkey, first, X25519PubkeyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("the anchored agreement key is unusable: %w", err)
		}
		k, err := DecodeLargeFixed(CESRMLKEM768Encap, second, MLKEM768EncapBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("the anchored encapsulation key is unusable: %w", err)
		}
		return x, k, nil
	}
	return nil, nil, ErrNotAnchored
}

// anchorList normalises the anchor field to one shape.
//
// An event reaches a verifier two ways and they do not produce the same Go
// type: decoded from JSON off the wire, the anchors are []interface{} holding
// map[string]interface{}; built in memory, they are []map[string]interface{}.
// A reader that handles only the first works on everything that arrived over a
// network and fails on the event this process just built — which is the harder
// failure to notice, because the code that builds an event is usually the code
// most confident it is correct.
//
// Anything else returns nothing, and the caller reports it as unanchored.
func anchorList(v interface{}) []map[string]interface{} {
	switch anchors := v.(type) {
	case []map[string]interface{}:
		return anchors
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(anchors))
		for _, entry := range anchors {
			if seal, ok := entry.(map[string]interface{}); ok {
				out = append(out, seal)
			}
		}
		return out
	default:
		return nil
	}
}

// keyList normalises the anchored key list, which is []string in memory and
// []interface{} once it has been through JSON — the same split as anchorList,
// one level down.
func keyList(v interface{}) []string {
	switch keys := v.(type) {
	case []string:
		return keys
	case []interface{}:
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			s, ok := k.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}
