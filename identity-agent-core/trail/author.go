// Package trail is the open, checkable part of a conversation's trail: the
// check that a person's statement is the person's, and the check that it was
// signed in time. Everything that keeps a trail (the store of conversations,
// the forwarding to an app, the reads, the delivery queue and its expiry) is an
// add-on's and is not here (ADR-068, ADR-069); the entries it writes are the
// chain's own (agentmessage.Record, checked offline by conversationbundle).
package trail

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/authorisation"
	"identity-agent-core/iacrypto"
)

// KeyRoster says whose a key is, from the Identity Agent's own records and
// never from the app.
type KeyRoster interface {
	// KeySpeaksFor says whether the key (signer identifier and verkey) was
	// approved to act as the person.
	KeySpeaksFor(person, signer, verkey string) bool
}

// AssertionRoster is a KeyRoster that also knows a key which cannot sign a plain
// statement. An Apple App Attest key signs only App Attest assertions, so the
// signature a person's statement carries for such a key is an assertion over the
// statement's SHA-256 (clientDataHash), not a signature over its bytes.
type AssertionRoster interface {
	KeyRoster
	// VerifyAssertion is handled=false for a key that signs plain statements
	// (the check is then agentmessage.VerifyPerson's). For a key that does not,
	// it is whether signature is the key's assertion over clientDataHash.
	VerifyAssertion(person, signer, verkey string, clientDataHash [32]byte, signature string) (handled bool, err error)
}

// Write is a person's statement as it is checked: the statement, the key that
// signed it and the signature. Salt and Words are what an add-on that keeps a
// trail carries beside it to the app; the checks here never read them. For a
// private agent's entry, Words is the ciphertext and Private is set.
type Write struct {
	Statement agentmessage.PersonStatement
	Verkey    string
	Signature string
	Salt      []byte
	Words     []byte
	Private   bool
}

// ReasonStale is why a statement signed outside the skew is refused.
const ReasonStale = "the statement was not signed within 5 minutes of now"

// Rejected is an attempt that proves no author: a malformed statement, a bad
// signature or a key that does not speak for the person. Nobody can be
// recorded as having tried, so nothing joins a trail; the caller's
// governance record says it happened.
type Rejected struct{ Reason string }

func (r *Rejected) Error() string { return "rejected: " + r.Reason }

// CheckAuthor is the one check that a person's statement is the person's: it is
// well formed, its signature holds under the key it names, it is for this
// Identity Agent, and the Identity Agent's own records say that key speaks for
// the person. A trail's write runs it first, and anything that admits a
// person's words before they reach a trail (an app speaking for a person, whose
// request is refused at the door) runs this same function, so there is not a
// second reader of what makes a statement a person's. The failure is a *Rejected.
func CheckAuthor(w Write, agent string, keys KeyRoster) error {
	s := w.Statement
	if err := verifyAuthor(w, keys); err != nil {
		return &Rejected{err.Error()}
	}
	if s.Agent != agent {
		return &Rejected{"the statement is for another Identity Agent"}
	}
	if keys == nil || !keys.KeySpeaksFor(s.From, s.Signer, w.Verkey) {
		return &Rejected{"the key does not speak for " + s.From}
	}
	return nil
}

// verifyAuthor is the signature check: a plain signature over the statement, or,
// for a key the roster says signs only assertions, its assertion over the
// statement's hash. A key that signs only assertions is never read as signing a
// plain statement, and the statement is checked well formed either way.
func verifyAuthor(w Write, keys KeyRoster) error {
	if ar, ok := keys.(AssertionRoster); ok {
		if err := w.Statement.Check(); err != nil {
			return err
		}
		// The identifier and the key must be one key, as agentbody.Verify holds.
		fromID, err := iacrypto.KeyFromMachineIdentifier(w.Statement.Signer)
		if err != nil {
			return err
		}
		fromKey, err := iacrypto.KeyFromMachineVerkey(w.Verkey)
		if err != nil {
			return err
		}
		if !bytes.Equal(fromID, fromKey) {
			return errors.New("the signer's identifier and its key are not the same key")
		}
		handled, err := ar.VerifyAssertion(w.Statement.From, w.Statement.Signer, w.Verkey, sha256.Sum256(w.Statement.Bytes()), w.Signature)
		if handled {
			return err
		}
	}
	return agentmessage.VerifyPerson(w.Statement, w.Verkey, w.Signature)
}

// CheckFresh holds a statement to the rule the verifier holds every person's
// entry to: signed within authorisation.Skew of now.
func CheckFresh(s agentmessage.PersonStatement, now time.Time) error {
	signed, err := time.Parse(time.RFC3339, s.Time)
	if err != nil {
		return &Rejected{ReasonStale}
	}
	if d := now.Sub(signed); d > authorisation.Skew || -d > authorisation.Skew {
		return &Rejected{ReasonStale}
	}
	return nil
}
