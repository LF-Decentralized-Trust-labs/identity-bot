package ownership

import (
	"encoding/json"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// The anchor: how an owner identity says, in its own key log, that it agreed
// to own one exact Identity Agent at one exact event (ADR-087, decision 1).
//
// It is KERI's event seal, {"i": M, "s": <sequence number, lowercase hex>,
// "d": <SAID>}, naming an establishment event E of the Identity Agent M, in
// the `a` field of an interaction event of the owner identity. Nothing marks
// it as an ownership anchor: a delegation approval has the same shape, and the
// two are told apart by what is sealed (decision 2), which is Check's work and
// not the seal's.

// AnchorSeal is the seal an owner identity writes to anchor event, an
// establishment event of the Identity Agent it agrees to own, as its exact
// bytes. For the owner named at founding the event is the inception, and the
// seal is {"i": M, "s": "0", "d": M}.
//
// It is written by drivers.EventSeal, the one writer of an event seal, as
// ordered JSON, because a seal's field order is part of the event that carries
// it. An interaction event, or an event of a delegated
// identity, is refused: neither can be owned in this sense. Whether the event
// names the owner that is about to anchor it is the caller's check to make
// before it signs.
func AnchorSeal(event []byte) (json.RawMessage, error) {
	ev, err := keri.ParseEvent(event)
	if err != nil {
		return nil, fmt.Errorf("the event to anchor is not readable: %w", err)
	}
	if !ev.Establishment() {
		return nil, fmt.Errorf("an anchor seals an establishment event, and this is a %s event", ev.Ilk)
	}
	if delegated(ev) {
		return nil, fmt.Errorf("a %s event belongs to a delegated identity, which is never owned", ev.Ilk)
	}
	return drivers.EventSeal(ev.Identifier, fmt.Sprintf("%x", ev.SN), ev.SAID)
}

// delegated is whether an event is one only a delegated identity has.
func delegated(ev *keri.Event) bool {
	return ev.Ilk == "dip" || ev.Ilk == "drt" || ev.Delegator != ""
}

// TheAnchorIn reads, from an owner identity's interaction as written, the one
// event seal it carries, as Check reads the seals of an interaction
// (elementsOf): its `a` list holds exactly one element, and that element is
// an event seal. Anything else is refused: no seal, more than one, another
// kind of seal, and one that cannot be read the same way by every reader.
// An interaction the writer of an owner log makes carries exactly one.
func TheAnchorIn(interaction []byte) (keri.Seal, error) {
	elements, err := elementsOf(interaction)
	if err != nil {
		return keri.Seal{}, fmt.Errorf("the event is not readable: %w", err)
	}
	if len(elements) != 1 || elements[0].unreadable || !elements[0].eventSeal {
		return keri.Seal{}, fmt.Errorf("an anchor carries exactly one event seal, and this event does not")
	}
	return elements[0].seal, nil
}
