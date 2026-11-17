// Package fingerprint is the salted fingerprint of some words (ADR-067): what a
// signed statement names in place of the words, so that a record can be kept and
// shown without anybody being able to confirm a short message by hashing
// guesses.
//
// It is a leaf, imported by a person's statement (agentmessage) and by a message
// between AI agents that two Identity Agents hold (agentpeer), neither of which
// may import the other.
package fingerprint

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"identity-agent-core/iacrypto"
)

// Salt sizes, in bytes.
const (
	MinSalt = 16
	MaxSalt = 1024
)

// Tag begins what version 1 is a digest of.
const Tag = "IA-FINGERPRINT-V1"

// NewSalt is a fresh random salt of the shortest allowed size. A signer makes
// one for every message.
func NewSalt() ([]byte, error) {
	salt := make([]byte, MinSalt)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Of is the version 1 fingerprint of words under a salt, as a CESR digest: the
// Blake3-256 of the tag, the salt's length as two bytes (big-endian), the salt
// and the words. For an entry held only as ciphertext, words is the ciphertext.
func Of(salt, words []byte) (string, error) {
	if len(salt) < MinSalt {
		return "", fmt.Errorf("a salt of at least %d bytes is needed", MinSalt)
	}
	if len(salt) > MaxSalt {
		return "", fmt.Errorf("a salt of at most %d bytes is allowed", MaxSalt)
	}
	pre := make([]byte, 0, len(Tag)+2+len(salt)+len(words))
	pre = append(pre, Tag...)
	pre = binary.BigEndian.AppendUint16(pre, uint16(len(salt)))
	pre = append(pre, salt...)
	pre = append(pre, words...)
	return iacrypto.Blake3QB64Must(pre), nil
}
