package conversationbundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"identity-agent-core/authorisation"
	"identity-agent-core/didcomm"
)

// TypeTrailHead is the message type of a head statement: the Identity Agent's
// signed word, at a time, of how many entries a conversation has committed and
// the hash of the newest (ADR-068). It is signed and never routed, so it is not
// a type the message endpoint knows.
const TypeTrailHead = "trail-head"

// HeadStatement is what the Identity Agent signs about a conversation an app
// keeps: its count and its head, as it stood at IATime. An export carries one,
// so an offline reader can tell an end that was cut off from an end that was
// never longer.
type HeadStatement struct {
	Conversation string `json:"conversation"`
	// Count is the number of committed entries, which equals the newest seq.
	Count int `json:"count"`
	// Head is the hash of the newest committed entry (agentmessage.Hash), empty
	// when Count is 0.
	Head   string `json:"head"`
	IATime string `json:"ia_time"`
}

func (h HeadStatement) id() string { return fmt.Sprintf("trail-head:%s:%d", h.Conversation, h.Count) }

func (h HeadStatement) check() error {
	if h.Conversation == "" || h.Count < 0 || (h.Count == 0) != (h.Head == "") {
		return errors.New("a head statement names a conversation, and a head exactly when there is a count")
	}
	return nil
}

// SignHead has the Identity Agent sign a head statement as identityAgent, the
// identity that countersigns a person's entries. pack signs a message as that
// identity, as didcomm.PackSigned does.
func SignHead(identityAgent string, pack func(m *didcomm.JWM) (*didcomm.Envelope, error), h HeadStatement) (*didcomm.Envelope, error) {
	if err := h.check(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	return pack(&didcomm.JWM{
		ID: h.id(), Type: TypeTrailHead,
		From: "did:keri:" + identityAgent, To: []string{"did:keri:" + identityAgent},
		CreatedTime: h.IATime, Body: body,
	})
}

// OpenHead checks a head statement against the messaging keys of the Identity
// Agent that signed it, and returns what it says.
func OpenHead(signer *didcomm.DID, env *didcomm.Envelope) (HeadStatement, error) {
	jwm, err := didcomm.UnpackSigned(signer, env)
	if err != nil {
		return HeadStatement{}, err
	}
	if jwm.Type != TypeTrailHead {
		return HeadStatement{}, fmt.Errorf("%q is not a head statement", jwm.Type)
	}
	var h HeadStatement
	if err := json.Unmarshal(jwm.Body, &h); err != nil {
		return HeadStatement{}, errors.New("the head statement is unreadable")
	}
	if err := h.check(); err != nil {
		return HeadStatement{}, err
	}
	if jwm.ID != h.id() {
		return HeadStatement{}, errors.New("the head statement's id is not the one signed")
	}
	if _, err := time.Parse(time.RFC3339Nano, h.IATime); err != nil {
		return HeadStatement{}, errors.New("the head statement carries no time")
	}
	return h, nil
}

// openHead reads the bundle's head statement, when it carries one, before the
// entries are read: what the Identity Agent says it had committed decides which
// of the bundle's entries are the conversation. A statement that cannot be read
// is a fault and decides nothing.
func (v *verifier) openHead() {
	if v.b.Head == nil {
		return
	}
	signer, ok := v.dids[v.b.Root]
	if !ok {
		v.fault("head statement", "the bundle carries no messaging keys tied to %s, who signs it", v.b.Root)
		return
	}
	h, err := OpenHead(signer, v.b.Head)
	if err != nil {
		v.fault("head statement", "%v", err)
		return
	}
	if h.Conversation != v.b.Conversation {
		v.fault("head statement", "it is about conversation %s, not %s", h.Conversation, v.b.Conversation)
		return
	}
	at, aerr := time.Parse(time.RFC3339Nano, h.IATime)
	exported, eerr := time.Parse(time.RFC3339Nano, v.b.ExportedAt)
	switch {
	case aerr != nil || eerr != nil:
		v.fault("head statement", "the export's time or the statement's cannot be read, so it cannot be shown the statement is not dated after the export")
	case at.After(exported.Add(authorisation.Skew)):
		v.fault("head statement", "it is dated after the export")
	}
	v.head = &h
	v.holdCopy()
}

// holdCopy checks the bundle's entries against the head statement with
// CheckCopy, once, so that the entries read as the conversation are the ones it
// chose by place, from the head back, whatever order the bundle lists them in.
// A copy it cannot read or that does not match is left to checkHead to fault,
// and the entries are then read by position so the rest of the bundle is still
// checked.
func (v *verifier) holdCopy() {
	if v.head == nil {
		return
	}
	byEnvelope := make(map[*didcomm.Envelope]Entry, len(v.b.Entries))
	envs := make([]*didcomm.Envelope, 0, len(v.b.Entries))
	for _, e := range v.b.Entries {
		if e.Envelope == nil {
			return // checkHead names the missing entry
		}
		byEnvelope[e.Envelope] = e
		envs = append(envs, e.Envelope)
	}
	v.copyRes, v.copyErr = CheckCopy(v.b.Conversation, envs, v.head.Count, v.head.Head, nil)
	if v.copyRes.Outcome != CopyMatches {
		return
	}
	v.committed = make([]Entry, 0, len(v.copyRes.Committed))
	for _, env := range v.copyRes.Committed {
		v.committed = append(v.committed, byEnvelope[env])
	}
	v.haveCommitted = true
}

// kept is the entries of the bundle that are the conversation: all of them,
// or, with a head statement the entries match, the ones CheckCopy chose as
// committed, one for each place in order. Entries past the count were never
// committed (ADR-068): they are not read, not listed in the report as messages,
// and only counted (Report.UncommittedEntries). With a head statement the
// entries do not match, the first count by position are read so the rest is
// still checked, and checkHead faults the mismatch.
func (v *verifier) kept() []Entry {
	if v.haveCommitted {
		return v.committed
	}
	if v.head != nil && v.head.Count < len(v.b.Entries) {
		return v.b.Entries[:v.head.Count]
	}
	return v.b.Entries
}

// checkHead holds the entries to the head statement openHead read. Without one
// nothing in a bundle fixes where the conversation ended, and the report says so
// for a conversation an app keeps, where an end can be cut off unseen.
func (v *verifier) checkHead() {
	if v.b.Head == nil {
		// Only a conversation a utility app keeps can be cut short unseen by the
		// anchors, and the bundle names no keeper, so it is told by a person's words
		// having been spoken through an app (an app's own request, or a person's
		// statement over a fingerprint of words the app keeps).
		for _, m := range v.r.Messages {
			if m.Sender == "app" || m.Sender == "statement" || m.AppAID != "" {
				v.cannotRuleOut("That entries were not cut off the end of the conversation after the last one an anchor fixes: a person spoke in it through an app that may keep it, and this bundle carries no head statement, so a copy cut short there looks whole.")
				break
			}
		}
		return
	}
	if v.head == nil {
		return // the statement was faulted in openHead
	}
	h := *v.head
	for i, e := range v.b.Entries {
		if e.Envelope == nil {
			v.fault("head statement", "entry %d is missing, so the chain cannot be held to the head", i+1)
			return
		}
	}
	v.r.UncommittedEntries = len(v.b.Entries) - len(v.kept())
	res, err := v.copyRes, v.copyErr
	switch {
	case res.Outcome == CopyMatches:
		v.cannotRuleOut(fmt.Sprintf("Whether the conversation went on after %s, when the Identity Agent signed its head: the end is shown as of that time, and an entry committed later is not in it.", h.IATime))
	case res.Outcome == "":
		v.fault("head statement", "the entries cannot be read against it: %v", err)
	default:
		v.fault("head statement", "the entries do not match the head the Identity Agent signed (%s): %v", res.Outcome, err)
	}
}
