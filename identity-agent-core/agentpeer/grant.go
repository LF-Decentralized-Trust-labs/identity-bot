package agentpeer

import "fmt"

// CapabilityMessagePeer is the grant entry that lets an AI agent message an AI
// agent that ANOTHER Identity Agent holds (ADR-080). It is not
// agent.message.send widened: that one means "an AI agent this same Identity
// Agent holds" and must never silently mean another Identity Agent's too. Nobody holds this one unless a grant names it.
const CapabilityMessagePeer = "agent.message.peer"

// The constraints of CapabilityMessagePeer: the contacts (other Identity Agents,
// by identifier) it reaches, and optionally which of their AI agents.
const (
	ConstraintContact = "contact"
	ConstraintAgent   = "agent"
)

// CheckPeerGrantShape refuses a grant's agent.message.peer entry that is not
// shaped as this package reads it: an object whose "contact" is a list
// of text, and whose "agent", when it is there at all, is a non-empty list of
// text. A narrowing constraint that is badly shaped must not widen the grant, so
// it is refused when the grant is issued and again when it is used.
func CheckPeerGrantShape(limits map[string]interface{}) error {
	raw, present := limits[CapabilityMessagePeer]
	if !present {
		return nil
	}
	c, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%s is an object with a %q list of contacts", CapabilityMessagePeer, ConstraintContact)
	}
	for k := range c {
		if k != ConstraintContact && k != ConstraintAgent {
			return fmt.Errorf("%s has no %q constraint", CapabilityMessagePeer, k)
		}
	}
	if !textList(c[ConstraintContact]) {
		return fmt.Errorf("%s: %q is a list of the contacts it may reach", CapabilityMessagePeer, ConstraintContact)
	}
	if v, there := c[ConstraintAgent]; there && !textList(v) {
		return fmt.Errorf("%s: %q, when it is given, is a non-empty list of AI agents", CapabilityMessagePeer, ConstraintAgent)
	}
	return nil
}

// textList says whether v is a non-empty list of non-empty text.
func textList(v interface{}) bool {
	l, ok := v.([]interface{})
	if !ok || len(l) == 0 {
		return false
	}
	for _, x := range l {
		if s, ok := x.(string); !ok || s == "" {
			return false
		}
	}
	return true
}

// CheckPeerGrant refuses a grant that does not name, outright, the contact
// whose AI agent its AI agent may message, and (when the grant names AI agents)
// the one asked. A missing constraint is no permission here, not no limit:
// reaching another Identity Agent fails closed, and so does a constraint that is
// not shaped as CheckPeerGrantShape says (an "agent" given as text, or as an
// empty list, is a refusal and never "every AI agent").
func CheckPeerGrant(limits map[string]interface{}, contact, agent string) error {
	if err := CheckPeerGrantShape(limits); err != nil {
		return fmt.Errorf("the grant does not let its AI agent message %s: %w", contact, err)
	}
	c, _ := limits[CapabilityMessagePeer].(map[string]interface{})
	if !listed(c[ConstraintContact], contact) {
		return fmt.Errorf("the grant does not let its AI agent message %s: %s needs an explicit %q constraint naming that contact", contact, CapabilityMessagePeer, ConstraintContact)
	}
	if _, narrowed := c[ConstraintAgent]; narrowed && !listed(c[ConstraintAgent], agent) {
		return fmt.Errorf("the grant does not let its AI agent message %s at %s", agent, contact)
	}
	return nil
}

func listed(v interface{}, want string) bool {
	l, _ := v.([]interface{})
	for _, x := range l {
		if s, ok := x.(string); ok && s == want {
			return true
		}
	}
	return false
}
