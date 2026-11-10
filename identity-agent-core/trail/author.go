// Package trail is the open, checkable part of a conversation's trail: the
// check that a person's statement is the person's, and the check that it was
// signed in time. Everything that keeps a trail (the store of conversations,
// the forwarding to an app, the reads, the delivery queue and its expiry) is an
// add-on's and is not here (ADR-068, ADR-069); the entries it writes are the
// chain's own (agentmessage.Record, checked offline by conversationbundle).
package trail

import (
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/authorisation"
)

// KeyRoster says whose a key is, from the Identity Agent's own records and
// never from the app.
type KeyRoster interface {
	// KeySpeaksFor says whether the key (signer identifier and verkey) was
	// approved to act as the person.
	KeySpeaksFor(person, signer, verkey string) bool
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
	if err := agentmessage.VerifyPerson(s, w.Verkey, w.Signature); err != nil {
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
