package agentmessage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"identity-agent-core/internal/strictjson"
)

// A person's entry in a conversation's one chain (ADR-068, extending ADR-047).
// The chain is Record and Hash: a person's salted-fingerprint entry, a refusal
// and the Identity Agent's note of how an entry ended are further kinds of
// Record in it, not a second record beside it.

// KindOutcome is the Identity Agent's own entry saying how an earlier,
// pending entry of a person's ended: kept by the app, or not. It is not a
// message, so it carries no sender's proof; the Identity Agent's
// countersignature is the proof.
const KindOutcome = "outcome"

// States an Outcome names.
const (
	OutcomeCommitted = "committed"
	OutcomeNotKept   = "not-kept"
	// OutcomeNotDelivered follows a committed entry whose sealed copy waited
	// in the delivery queue until its age ran out and was refused back to its
	// sender. The entry stays committed and readable; this says it did not
	// reach its recipient.
	OutcomeNotDelivered = "not-delivered"
	// OutcomeClosedUnanswered follows an AI agent's ask that was still
	// unanswered when its conversation was closed: the work under it is over,
	// and the AI agent that owed the answer is told. An answer that comes
	// after is still kept, and does not reopen the conversation.
	OutcomeClosedUnanswered = "closed-unanswered"
	// OutcomeBodyLost follows an AI agent's ask that was still unanswered when
	// the body that held it was lost, revoked or archived, so nothing is working
	// on it any more. It is addressed to the one who asked, who is told, and
	// ends the ask once, in a conversation that is still open.
	OutcomeBodyLost = "body-lost"
)

// PersonProof is the sender's own proof for an entry a person signed as a
// statement over the fingerprint of their words (ADR-067): the statement, the
// key that signed it and the signature. It holds no words.
type PersonProof struct {
	Statement PersonStatement `json:"statement"`
	Verkey    string          `json:"verkey"`
	Signature string          `json:"signature"`
}

// Verify checks the signature on the statement against the key it names.
func (p PersonProof) Verify() error { return VerifyPerson(p.Statement, p.Verkey, p.Signature) }

// Outcome is how a pending entry ended. The entry itself is never changed: the
// chain is append-only, so the outcome is an entry of its own that follows it.
type Outcome struct {
	// Entry is the id of the entry it is about ("e" and its seq).
	Entry string `json:"entry"`
	// State is OutcomeCommitted, OutcomeNotKept or OutcomeNotDelivered.
	State string `json:"state"`
	// Reason is why an entry was not kept; empty for a committed one.
	Reason string `json:"reason,omitempty"`
}

// EntryID is the id of the entry at a place in a conversation. The app that
// keeps the words of a person's entry keeps them under it.
func EntryID(seq int) string { return fmt.Sprintf("e%d", seq) }

// FingerprintVersion is the fingerprint version of the words a person's entry
// is a fingerprint of, and whether the entry is a person's at all. An entry
// from a paired app's signed request holds the words unsalted (version 0); a
// person's statement names its version (ADR-067). An AI agent's entry and an
// outcome are not a person's: the cut-over (CheckVersionOrder) is about a
// person's words, and an AI agent's statement does not name a version yet
// (ADR-068).
func (r Record) FingerprintVersion() (int, bool) {
	switch {
	case r.PersonProof != nil:
		return r.PersonProof.Statement.FingerprintVersion, true
	case r.ControllerProof != nil && r.ControllerProof.StatementOnly() && r.ControllerProof.PersonStatement != nil:
		return r.ControllerProof.PersonStatement.Statement.FingerprintVersion, true
	case r.ControllerProof != nil:
		return FingerprintV0, true
	}
	return 0, false
}

// checkPersonProof checks a person's statement entry against the record that
// carries it: the signature holds, and the record says what was signed.
func (r Record) checkPersonProof() error {
	p := r.PersonProof
	if r.Statement != nil || r.ControllerProof != nil {
		return errors.New("a message carries one sender's proof, not two")
	}
	st := p.Statement
	if err := p.Verify(); err != nil {
		return err
	}
	if r.Kind != st.Kind || r.From != Person(st.From) || r.To != st.To || r.InReplyTo != st.InReplyTo ||
		r.BodyHash != st.Fingerprint || r.Conversation != st.Conversation {
		return errors.New("the record does not say what the person signed")
	}
	if r.CiphertextHash != "" && r.CiphertextHash != st.Fingerprint {
		return errors.New("the ciphertext hash is not the statement's fingerprint")
	}
	if r.Outcome != nil {
		return errors.New("a person's entry is not an outcome")
	}
	if strings.ContainsAny(r.Refusal, "\r\n") {
		return errors.New("a refusal's reason may not contain a line break")
	}
	return nil
}

// checkOutcome checks an outcome entry: the Identity Agent's note, with no
// sender's proof.
func (r Record) checkOutcome() error {
	o := r.Outcome
	if r.Statement != nil || r.ControllerProof != nil || r.PersonProof != nil || r.Refusal != "" || r.CiphertextHash != "" {
		return errors.New("an outcome carries no sender's proof")
	}
	if r.Kind != KindOutcome || o.Entry == "" || o.Entry != r.InReplyTo {
		return errors.New("an outcome names the entry it is about")
	}
	switch o.State {
	case OutcomeCommitted:
		if o.Reason != "" {
			return errors.New("a committed entry has no reason")
		}
	case OutcomeNotKept:
		if o.Reason == "" {
			return errors.New("a not-kept entry gives its reason")
		}
	case OutcomeNotDelivered:
		if o.Reason == "" {
			return errors.New("a not-delivered entry gives its reason")
		}
	case OutcomeClosedUnanswered:
		if o.Reason != "" {
			return errors.New("a closed-unanswered entry has no reason: the close is the reason")
		}
	case OutcomeBodyLost:
		if o.Reason == "" {
			return errors.New("a body-lost entry gives its reason")
		}
	default:
		return fmt.Errorf("%q is not an outcome", o.State)
	}
	if strings.ContainsAny(o.Entry+o.Reason, "\r\n") {
		return errors.New("an outcome field may not contain a line break")
	}
	return nil
}

// UnmarshalJSON reads a statement exactly as its contract says
// (signed-fingerprint.md), as another implementation reads it: internal/strictjson
// refuses a key spelt in another case, a key twice and an unknown key, and a
// null is refused here, where Go's decoder would leave the field empty. Two
// readers must agree on what a statement is at all, or one of them is checking
// a statement the other never saw.
func (s *PersonStatement) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("a statement is a JSON object")
	}
	for k, v := range fields {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fmt.Errorf("%q is null: leave a field out instead", k)
		}
	}
	type plain PersonStatement // without this method, so Decode does not read itself
	var p plain
	if err := strictjson.Decode(data, &p); err != nil {
		return err
	}
	*s = PersonStatement(p)
	return nil
}

// RecordedAt is the time the Identity Agent stamped on a record.
func (r Record) RecordedAt() (time.Time, error) { return time.Parse(time.RFC3339Nano, r.IATime) }
