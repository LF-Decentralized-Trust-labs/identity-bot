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

// checkHead reads the bundle's head statement, when it carries one, and holds
// the entries to it. Without one nothing in a bundle fixes where the
// conversation ended, and the report says so.
func (v *verifier) checkHead() {
	if v.b.Head == nil {
		v.cannotRuleOut("That entries were not cut off the end of the conversation after the last one an anchor fixes: this bundle carries no head statement, so a copy cut short there looks whole.")
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
	envs := make([]*didcomm.Envelope, 0, len(v.b.Entries))
	for i, e := range v.b.Entries {
		if e.Envelope == nil {
			v.fault("head statement", "entry %d is missing, so the chain cannot be held to the head", i+1)
			return
		}
		envs = append(envs, e.Envelope)
	}
	// Entries past the count were never committed and are left out; the rest
	// are held to the statement's count and head.
	outcome, err := CheckCopy(v.b.Conversation, envs, h.Count, h.Head)
	switch {
	case outcome == CopyMatches:
	case outcome == "":
		v.fault("head statement", "the entries cannot be read against it: %v", err)
	default:
		v.fault("head statement", "the entries do not match the head the Identity Agent signed (%s): %v", outcome, err)
	}
}
