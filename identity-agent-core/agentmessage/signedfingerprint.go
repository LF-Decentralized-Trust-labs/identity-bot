package agentmessage

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/iacrypto"
)

// A person signs a salted fingerprint of their words, never the words
// (ADR-067). This file is the fingerprint and the statement the person signs.
// It does not decide who may write or what is kept; the Identity Agent does.

// Fingerprint versions.
const (
	// FingerprintV0 is HashBody over the words: no salt. It verifies only a
	// record made before the salted fingerprint existed; a new write that
	// carries it is refused (PersonStatement.Check).
	FingerprintV0 = 0
	// FingerprintV1 is Blake3-256 over the tag, the salt's length, the salt and
	// the words.
	FingerprintV1 = 1
)

// Salt sizes, in bytes.
const (
	MinSalt = 16
	MaxSalt = 1024
)

const fingerprintTagV1 = "IA-FINGERPRINT-V1"

// NewSalt is a fresh random salt of the shortest allowed size. A signer makes
// one for every message.
func NewSalt() ([]byte, error) {
	salt := make([]byte, MinSalt)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Fingerprint is the version 1 fingerprint of words under a salt. For an
// entry the Identity Agent holds only as ciphertext, words is the ciphertext.
func Fingerprint(salt, words []byte) (string, error) {
	if len(salt) < MinSalt {
		return "", fmt.Errorf("a salt of at least %d bytes is needed", MinSalt)
	}
	if len(salt) > MaxSalt {
		return "", fmt.Errorf("a salt of at most %d bytes is allowed", MaxSalt)
	}
	pre := make([]byte, 0, len(fingerprintTagV1)+2+len(salt)+len(words))
	pre = append(pre, fingerprintTagV1...)
	pre = binary.BigEndian.AppendUint16(pre, uint16(len(salt)))
	pre = append(pre, salt...)
	pre = append(pre, words...)
	return iacrypto.Blake3QB64Must(pre), nil
}

// CheckFingerprint says whether fingerprint is the one of words under salt, at
// the version stated. Version 0 has no salt and is checked only when
// recorded is true: the caller is verifying a record made before version 1.
func CheckFingerprint(version int, salt, words []byte, fingerprint string, recorded bool) error {
	var got string
	switch version {
	case FingerprintV0:
		if !recorded {
			return errors.New("an unsalted fingerprint (version 0) is accepted only in a record made before salted ones")
		}
		if len(salt) != 0 {
			return errors.New("a version 0 fingerprint has no salt")
		}
		got = HashBody(words)
	case FingerprintV1:
		var err error
		if got, err = Fingerprint(salt, words); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%d is not a fingerprint version", version)
	}
	if got != fingerprint {
		return errors.New("the words do not match their fingerprint")
	}
	return nil
}

// CheckVersionOrder says whether the fingerprint versions of an ordered record
// (a conversation's entries, oldest first) respect the cut-over: version 0 is
// legitimate only before the first version 1 entry, so once a record has a
// salted fingerprint no unsalted one may follow it (ADR-067). A verifier passes
// recorded=true to CheckFingerprint only for an entry this accepts as old.
func CheckVersionOrder(versions []int) error {
	salted := false
	for i, v := range versions {
		switch v {
		case FingerprintV0:
			if salted {
				return fmt.Errorf("entry %d has an unsalted fingerprint (version 0) after a salted one", i+1)
			}
		case FingerprintV1:
			salted = true
		default:
			return fmt.Errorf("entry %d: %d is not a fingerprint version", i+1, v)
		}
	}
	return nil
}

// Kinds of entry a person signs.
const (
	PersonKindMessage = "message"
	PersonKindAsk     = "ask"
	PersonKindSplit   = "split"
	PersonKindHandOff = "hand-off"
	PersonKindClose   = "close"
	PersonKindReopen  = "reopen"
	// PersonKindLimit raises a conversation's turn limit. Its words are the new
	// limit in decimal digits, fingerprinted like any other words.
	PersonKindLimit = "limit"
)

// PersonStatement is what a person's device or session signs: a statement
// over the fingerprint of their words, never the words (ADR-067).
type PersonStatement struct {
	// Agent is the Identity Agent that holds the conversation. A conversation
	// id is made by whoever opens it, so it is unique only within one Identity
	// Agent; naming the Identity Agent keeps a statement from being replayed
	// into another's conversation of the same id (ADR-067).
	Agent        string `json:"agent"`
	Conversation string `json:"conversation"`
	// MessageID is the sender's own id for the message, bound into the
	// signature.
	MessageID string `json:"message_id"`
	Kind      string `json:"kind"`
	From      string `json:"from"`
	// Signer is the identifier of the key that signs: the device or session.
	Signer string `json:"signer"`
	// To is the AI agent addressed, the new owner of a hand-off, or a split's
	// owner. It is empty for a close and a reopen.
	To        string `json:"to,omitempty"`
	InReplyTo string `json:"in_reply_to,omitempty"`
	// RangeFirst and RangeLast are the entries a split carries, and only a
	// split names them.
	RangeFirst         string `json:"range_first,omitempty"`
	RangeLast          string `json:"range_last,omitempty"`
	Nonce              string `json:"nonce"`
	Time               string `json:"time"`
	FingerprintVersion int    `json:"fingerprint_version"`
	Fingerprint        string `json:"fingerprint"`
}

// Bytes is the string a person signs: IA-PERSON-MSG-V1 and then one field per
// line in a fixed order (agent first), joined by a newline, no trailing newline.
func (s PersonStatement) Bytes() []byte {
	return []byte(strings.Join([]string{
		"IA-PERSON-MSG-V1",
		s.Agent, s.Conversation, s.MessageID, s.Kind, s.From, s.Signer, s.To, s.InReplyTo,
		s.RangeFirst, s.RangeLast, s.Nonce, s.Time,
		fmt.Sprint(s.FingerprintVersion), s.Fingerprint,
	}, "\n"))
}

// Check refuses a statement that is not well formed, before anything is
// verified. It refuses fingerprint version 0: a new statement is always
// salted.
func (s PersonStatement) Check() error {
	for name, v := range map[string]string{
		"agent": s.Agent, "conversation": s.Conversation, "message_id": s.MessageID, "kind": s.Kind,
		"from": s.From, "signer": s.Signer, "nonce": s.Nonce, "time": s.Time,
		"fingerprint": s.Fingerprint,
	} {
		if v == "" {
			return fmt.Errorf("the statement has no %s", name)
		}
	}
	for _, v := range []string{s.Agent, s.Conversation, s.MessageID, s.Kind, s.From, s.Signer, s.To,
		s.InReplyTo, s.RangeFirst, s.RangeLast, s.Nonce, s.Time, s.Fingerprint} {
		if strings.ContainsAny(v, "\r\n") {
			return errors.New("a statement field may not contain a line break")
		}
	}
	switch s.Kind {
	case PersonKindMessage, PersonKindAsk, PersonKindHandOff:
		if s.To == "" {
			return fmt.Errorf("a %s must name who it is to", s.Kind)
		}
	case PersonKindSplit:
		if s.To == "" {
			return errors.New("a split must name its owner")
		}
		if s.RangeFirst == "" || s.RangeLast == "" {
			return errors.New("a split must name the range it carries")
		}
	case PersonKindClose, PersonKindReopen, PersonKindLimit:
		if s.To != "" {
			return fmt.Errorf("a %s names no recipient", s.Kind)
		}
	default:
		return fmt.Errorf("%q is not a kind of entry a person signs", s.Kind)
	}
	if s.Kind != PersonKindSplit && (s.RangeFirst != "" || s.RangeLast != "") {
		return fmt.Errorf("only a split names a range, not a %s", s.Kind)
	}
	switch s.FingerprintVersion {
	case FingerprintV1:
	case FingerprintV0:
		return errors.New("a new statement may not carry an unsalted fingerprint (version 0)")
	default:
		return fmt.Errorf("%d is not a fingerprint version", s.FingerprintVersion)
	}
	if agentbody.CheckNonce(s.Nonce) != nil {
		return fmt.Errorf("the statement needs a nonce of at least %d characters", agentbody.MinNonce)
	}
	if _, err := time.Parse(time.RFC3339, s.Time); err != nil {
		return errors.New("the statement's time must be RFC 3339")
	}
	return nil
}

// SignPerson is a person's device or session signing its statement.
func SignPerson(signer agentbody.Signer, s PersonStatement) (string, error) {
	if err := s.Check(); err != nil {
		return "", err
	}
	id, _, err := agentbody.Identity(signer)
	if err != nil {
		return "", err
	}
	if id != s.Signer {
		return "", errors.New("the statement names another key as its signer")
	}
	return agentbody.Sign(signer, s.Bytes())
}

// VerifyPerson checks a person's signature on a statement against the key it
// names as its signer. Whether that key speaks for the person is the
// Identity Agent's to decide, not this check's.
func VerifyPerson(s PersonStatement, verkey, signature string) error {
	if err := s.Check(); err != nil {
		return err
	}
	return agentbody.Verify(s.Signer, verkey, signature, s.Bytes())
}

// VerifyPersonWords is VerifyPerson and then the check that the words and salt
// are the ones the statement's fingerprint is of.
func VerifyPersonWords(s PersonStatement, verkey, signature string, salt, words []byte) error {
	if err := VerifyPerson(s, verkey, signature); err != nil {
		return err
	}
	return CheckFingerprint(s.FingerprintVersion, salt, words, s.Fingerprint, false)
}
