package recovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"identity-agent-core/backup"
)

// PairwiseVerification describes one regenerated HD pairwise identity.
type PairwiseVerification struct {
	ContactIndex      int    `json:"contact_index"`
	ContactAID        string `json:"contact_aid,omitempty"`
	PairwiseAID       string `json:"pairwise_aid"`
	PublicKeyB64      string `json:"public_key_b64"`
	ExpectedPublicKey string `json:"expected_public_key"`
	Matched           bool   `json:"matched"`
}

// ErrPairwiseMismatch is returned when a derived pairwise key does not match backup records.
type ErrPairwiseMismatch struct {
	ContactIndex int
	Expected     string
	Derived      string
	PairwiseAID  string
}

func (e *ErrPairwiseMismatch) Error() string {
	return fmt.Sprintf(
		"pairwise public key mismatch at contact index %d (aid %s): expected %s, derived %s",
		e.ContactIndex, e.PairwiseAID, e.Expected, e.Derived,
	)
}

// PairwiseAIDFromPublicKey derives the KERI-style E-prefixed pairwise AID from an Ed25519 public key.
func PairwiseAIDFromPublicKey(pub ed25519.PublicKey) string {
	enc := base64.RawURLEncoding.EncodeToString(pub)
	if len(enc) > 43 {
		enc = enc[:43]
	}
	return "E" + enc
}

// DerivePairwiseAtIndex derives seed, public key, and P-AID for a contact index.
func DerivePairwiseAtIndex(bip39Seed []byte, contactIndex, keyIndex int) (ed25519.PublicKey, string, error) {
	seed, err := backup.DerivePairwiseSeed(bip39Seed, contactIndex, keyIndex)
	if err != nil {
		return nil, "", err
	}
	pub := backup.PairwisePublicKey(seed)
	return pub, PairwiseAIDFromPublicKey(pub), nil
}

// expectedPairwisePublicKey returns the stored expectation for a contact record.
// Prefer explicit pairwise_public_key; fall back to public_key for legacy archives.
func expectedPairwisePublicKey(c ContactPairwiseExpectation) string {
	if c.PairwisePublicKey != "" {
		return c.PairwisePublicKey
	}
	return c.PublicKey
}

// VerifyPairwiseContacts regenerates HD P-AIDs from the seed and hard-fails on pubkey mismatch.
func VerifyPairwiseContacts(bip39Seed []byte, contacts []ContactPairwiseExpectation) ([]PairwiseVerification, error) {
	results := make([]PairwiseVerification, 0, len(contacts))
	for i, contact := range contacts {
		expected := expectedPairwisePublicKey(contact)
		if expected == "" {
			continue
		}

		pub, aid, err := DerivePairwiseAtIndex(bip39Seed, i, 0)
		if err != nil {
			return nil, fmt.Errorf("derive pairwise at index %d: %w", i, err)
		}
		derived := NormalizePublicKeyB64(pub)

		matched, normExpected, normDerived, err := PublicKeysEqual(expected, derived)
		if err != nil {
			return nil, fmt.Errorf("contact index %d: %w", i, err)
		}
		if !matched {
			return nil, &ErrPairwiseMismatch{
				ContactIndex: i,
				Expected:     normExpected,
				Derived:      normDerived,
				PairwiseAID:  aid,
			}
		}

		results = append(results, PairwiseVerification{
			ContactIndex:      i,
			ContactAID:        contact.AID,
			PairwiseAID:       aid,
			PublicKeyB64:      normDerived,
			ExpectedPublicKey: normExpected,
			Matched:           true,
		})
	}
	return results, nil
}

// NormalizePublicKeyB64 encodes an Ed25519 public key as standard base64 (no padding).
func NormalizePublicKeyB64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// PublicKeysEqual compares two base64-encoded Ed25519 public keys with encoding normalization.
func PublicKeysEqual(a, b string) (matched bool, normA, normB string, err error) {
	rawA, err := decodePublicKeyBytes(a)
	if err != nil {
		return false, "", "", fmt.Errorf("decode expected key: %w", err)
	}
	rawB, err := decodePublicKeyBytes(b)
	if err != nil {
		return false, "", "", fmt.Errorf("decode derived key: %w", err)
	}
	normA = base64.StdEncoding.EncodeToString(rawA)
	normB = base64.StdEncoding.EncodeToString(rawB)
	return string(rawA) == string(rawB), normA, normB, nil
}

func decodePublicKeyBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty public key")
	}
	if strings.HasPrefix(s, "B") {
		s = s[1:]
	}
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
		return raw, nil
	}
	if raw, err := base64.URLEncoding.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
		return raw, nil
	}
	return nil, fmt.Errorf("unrecognized public key encoding")
}
