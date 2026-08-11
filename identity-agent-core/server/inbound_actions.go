package server

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"identity-agent-core/didcomm"
)

// What happens when an action arrives inside an envelope.
//
// The envelope has always had a payload type and a registry of what those types
// are. What it never had was anywhere to send them: the inbound router forwarded
// everything to an optional overlay hook and otherwise logged, so eleven of the
// thirteen declared types had no producer and no consumer. Meanwhile the actions
// themselves — contacts, credentials, login — grew up somewhere else, dispatched
// on an integer and carried in the clear.
//
// So the encryption ended up with nothing to carry and the actions ended up with
// nothing to protect them, and each half looked finished from where it stood.
//
// This is the missing half of the envelope: the same dispatch the Ask registry
// already demonstrates, on the type the envelope already carries. An action
// registers here and arrives authenticated, encrypted, fresh and un-replayed,
// because the envelope established all of that before anything was dispatched.
//
// The table is additive on purpose. A type with no entry falls through to the
// overlay hook and then to being stored and logged, which is what happened to
// everything before — so adding an action is a new registration, and nothing
// that works today stops working while the actions move across one at a time.

// InboundMessage is one action that arrived inside an envelope, after the
// envelope established who sent it.
//
// FromAID is not a claim in the body. It comes from the envelope header, which
// only the holder of that identity's key could have produced — which is the
// whole reason for moving actions in here.
type InboundMessage struct {
	ToAID     string
	FromAID   string
	Type      string
	Body      json.RawMessage
	MessageID string
}

// InboundAction is the behaviour for one payload type.
//
// Perform runs after the envelope has been opened, the sender authenticated,
// freshness checked and replay refused. It does not repeat any of that. What it
// still must decide is whether this sender may do THIS — being able to talk is
// not the same as being allowed to act.
type InboundAction interface {
	Type() string
	Perform(s *CoreServer, in InboundMessage) error
}

var inboundActions = struct {
	sync.RWMutex
	m map[string]InboundAction
}{m: map[string]InboundAction{}}

// registerInboundAction wires an action to its payload type.
//
// Refuses a type the envelope layer does not know, because an envelope carrying
// it would be rejected on unpack before ever reaching here — a registration that
// could never fire, which is worse than none for looking like coverage.
func registerInboundAction(a InboundAction) {
	if !knownEnvelopeType(a.Type()) {
		panic(fmt.Sprintf("inbound action %q is not a registered envelope type, so nothing could ever "+
			"deliver it — register the type first", a.Type()))
	}
	inboundActions.Lock()
	defer inboundActions.Unlock()
	if _, taken := inboundActions.m[a.Type()]; taken {
		panic(fmt.Sprintf("two actions claim payload type %q", a.Type()))
	}
	inboundActions.m[a.Type()] = a
}

func lookupInboundAction(t string) (InboundAction, bool) {
	inboundActions.RLock()
	defer inboundActions.RUnlock()
	a, ok := inboundActions.m[t]
	return a, ok
}

// dispatchInbound performs the action an envelope carried, if one is registered.
//
// Reports whether it handled the message so the caller can fall through to the
// behaviour that existed before rather than swallowing anything.
func (s *CoreServer) dispatchInbound(in InboundMessage) bool {
	action, ok := lookupInboundAction(in.Type)
	if !ok {
		return false
	}
	if err := action.Perform(s, in); err != nil {
		// Logged rather than returned to the sender. The envelope has already
		// been accepted, and telling a counterparty why an action failed on the
		// inside is how a probe learns the shape of what is in here.
		log.Printf("[didcomm] %s from %s could not be carried out: %v", in.Type, in.FromAID, err)
	}
	return true
}

// knownEnvelopeType asks the envelope layer whether it would carry this type at
// all. Kept here so the registry has one question to ask rather than importing
// the envelope's internals.
func knownEnvelopeType(t string) bool { return didcomm.KnownType(t) }
