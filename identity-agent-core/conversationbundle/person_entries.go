package conversationbundle

import (
	"fmt"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/authorisation"
)

// A person's entry signed as a statement over the fingerprint of their words
// is an entry of the same chain as any other (ADR-068, extending ADR-047): a
// refusal and the Identity Agent's note of how an entry ended are entries
// beside it. This file is what the one verifier checks of them. The rules that
// decide who may write are the Identity Agent's own, from its roster, and are
// not replayed here; what is checked is what the chain can show.

// personEntry is one entry a person signed as a statement, as the chain has it.
type personEntry struct {
	where string
	rec   agentmessage.Record
	// state is "refused", "pending", or an outcome's state.
	state string
	// salt and words are what the bundle carries for it; hasWords says whether
	// it carries any.
	salt, words []byte
	hasWords    bool
	// notDelivered is set by the one note that a committed entry's message was
	// not delivered; the entry stays committed.
	notDelivered bool
}

func (v *verifier) person() {
	if v.people == nil {
		v.people, v.used = map[string]*personEntry{}, map[string]bool{}
	}
}

// checkVersionOrder holds a person's unsalted words (version 0: the signed
// request of a paired app, which carries them) to the cut-over of ADR-067:
// they are old only before the first salted entry of the record, and once the
// record has a salted one no unsalted one may follow. An AI agent's entry and
// an outcome are no person's words and are not counted.
func (v *verifier) checkVersionOrder(where string, rec agentmessage.Record) {
	ver, ok := rec.FingerprintVersion()
	if !ok {
		return
	}
	v.versions = append(v.versions, ver)
	if ver == agentmessage.FingerprintV0 {
		if err := agentmessage.CheckVersionOrder(v.versions); err != nil {
			v.fault(where, "the person's words are unsalted (version 0) but follow a salted entry, so they are not from before salted ones: %v", err)
		}
	}
}

// notePersonEntry takes in a person's statement entry and the words the bundle
// carries beside it, if any.
func (v *verifier) notePersonEntry(where string, rec agentmessage.Record, e Entry, body []byte, bodyErr error) {
	v.person()
	pe := &personEntry{where: where, rec: rec, state: "pending"}
	if rec.MessageID != agentmessage.EntryID(rec.Seq) {
		v.fault(where, "a person's entry is named for its place in the conversation (%s)", agentmessage.EntryID(rec.Seq))
	}
	if rec.Refusal != "" {
		pe.state = "refused"
	}
	if bodyErr != nil || len(body) > agentmessage.MaxBody {
		v.fault(where, "the words carried are unreadable or too long")
	} else if e.Salt != "" {
		salt, err := decode(e.Salt)
		if err != nil {
			v.fault(where, "the salt carried is unreadable")
		} else {
			pe.salt, pe.words, pe.hasWords = salt, body, true
		}
	} else if len(body) > 0 {
		v.fault(where, "words are carried without the salt of their fingerprint")
	}
	v.people[rec.MessageID] = pe
}

// checkPersonStatement checks a person's statement entry: it names this
// Identity Agent, was signed near the time the Identity Agent took it, answers
// only an entry that was kept, and a write the Identity Agent allowed does not
// reuse an id or a nonce its author had already used.
func (v *verifier) checkPersonStatement(where string, rec agentmessage.Record, at time.Time, m *Message) {
	v.person()
	st := rec.PersonProof.Statement
	m.Sender, m.Person = "statement", st.From
	if st.Agent != v.b.Root {
		v.fault(where, "the person signed it for Identity Agent %q, not for this organisation %s", st.Agent, v.b.Root)
	}
	if signedAt, err := time.Parse(time.RFC3339, st.Time); err != nil || absDuration(at.Sub(signedAt)) > authorisation.Skew {
		v.fault(where, "the statement was not signed within %s of when the Identity Agent took it", authorisation.Skew)
	}
	v.cannotRuleOut("Which person a device's or session's key speaks for, in an entry signed as a statement over a fingerprint, is the Identity Agent's word: no credential in the bundle shows it. Whether that Identity Agent's rules allowed a write (who owns the conversation, who may be addressed) is its word as well.")
	keys := []string{"id " + st.From + "\n" + st.MessageID, "nonce " + st.From + "\n" + st.Nonce}
	if rec.Refusal != "" {
		// A refusal is recorded wherever it falls, and it uses up its author's
		// id and nonce: a later write may not have them, and an id-reuse
		// refusal is the one entry that names an id already used.
		for _, k := range keys {
			v.used[k] = true
		}
		return
	}
	if st.InReplyTo != "" {
		prompt, ok := v.entries[st.InReplyTo]
		switch {
		case !ok || prompt.MessageID == rec.MessageID:
			v.fault(where, "it answers %s, which is not an earlier entry of this conversation", st.InReplyTo)
		default:
			if p, person := v.people[st.InReplyTo]; person && p.state != agentmessage.OutcomeCommitted {
				v.fault(where, "it answers %s, which was %s when it was written, and only a kept entry is answered", st.InReplyTo, p.state)
			}
		}
	}
	for _, k := range keys {
		if v.used[k] {
			v.fault(where, "it reuses an id or a nonce its author had already used in this conversation, which the Identity Agent allows only as a refusal")
		}
		v.used[k] = true
	}
}

// checkOutcome checks the Identity Agent's note of how an entry ended: it is
// the Identity Agent's own, about an entry of a person's that was pending, and
// it ends it once.
func (v *verifier) checkOutcome(where string, rec agentmessage.Record, m *Message) {
	v.person()
	m.Sender = "identity agent"
	if rec.From != v.b.Root {
		v.fault(where, "an outcome is the Identity Agent's, and this one is from %s", rec.From)
	}
	pe, ok := v.people[rec.Outcome.Entry]
	switch {
	case !ok || pe.rec.Seq >= rec.Seq:
		v.fault(where, "it says how %s ended, which is not an earlier entry of a person's", rec.Outcome.Entry)
		return
	case rec.Outcome.State == agentmessage.OutcomeNotDelivered:
		// Only a kept entry's message is carried, and it fails to arrive once.
		if pe.state != agentmessage.OutcomeCommitted || pe.notDelivered {
			v.fault(where, "it says %s was not delivered, but only a kept entry is delivered, and its delivery fails once", rec.Outcome.Entry)
			return
		}
		pe.notDelivered = true
		return
	case pe.state != "pending":
		v.fault(where, "it says how %s ended, but that entry was already %s", rec.Outcome.Entry, pe.state)
		return
	}
	pe.state = rec.Outcome.State
}

// finishPeople checks, once the whole chain has been read, the words the
// bundle carries against the fingerprints their entries are signed over: with
// each entry's end now known, words offered for an entry that was refused or
// not kept are a fault, and a kept entry's words are recomputed.
func (v *verifier) finishPeople() {
	pending, unwords := 0, 0
	for i := range v.b.Entries {
		pe := v.people[fmt.Sprintf("e%d", i+1)]
		if pe == nil {
			continue
		}
		st := pe.rec.PersonProof.Statement
		switch {
		case pe.hasWords && (pe.state == "refused" || pe.state == agentmessage.OutcomeNotKept):
			v.fault(pe.where, "it was %s, so no words are expected for it", pe.state)
		case pe.hasWords:
			if err := agentmessage.CheckFingerprint(st.FingerprintVersion, pe.salt, pe.words, st.Fingerprint, false); err != nil {
				v.fault(pe.where, "the words carried are not the words it was signed over: %v", err)
			}
		case pe.state == agentmessage.OutcomeCommitted:
			unwords++
		}
		if pe.state == "pending" {
			pending++
		}
	}
	if unwords > 0 {
		v.cannotRuleOut(fmt.Sprintf("The words of %d kept entry(ies) are not in the bundle, so their fingerprints could not be recomputed: the app that keeps the words holds them.", unwords))
	}
	if pending > 0 {
		v.cannotRuleOut(fmt.Sprintf("%d entry(ies) were still pending when the conversation was exported, so whether the app kept them is not shown.", pending))
	}
}
