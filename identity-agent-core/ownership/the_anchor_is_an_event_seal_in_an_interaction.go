package ownership

import (
	"encoding/json"
	"fmt"

	keri "github.com/grapeid/keri-go"
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
// It is returned as ordered JSON, because a seal's field order is part of the
// event that carries it. An interaction event, or an event of a delegated
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
	return EventSeal(ev.Identifier, ev.SN, ev.SAID)
}

// EventSeal is KERI's event seal for the event of identifier at sequence
// number sn whose SAID is said, with the sequence number in lowercase hex and
// the fields in the order the specification lists.
func EventSeal(identifier string, sn uint64, said string) (json.RawMessage, error) {
	if identifier == "" || said == "" {
		return nil, fmt.Errorf("an event seal names an identifier and an event")
	}
	return json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"%x","d":%q}`, identifier, sn, said)), nil
}

// SealsOfInteraction is the event seals an interaction event carries, in
// order, read as keri-go reads any event's seals. It is empty for every other
// kind of event: an anchor is read only from an interaction event, because an
// event seal in an establishment event is already read as that identity's own
// owner seal (ADR-032), the other way round.
func SealsOfInteraction(ev *keri.Event) ([]keri.Seal, error) {
	if ev.Ilk != "ixn" {
		return nil, nil
	}
	return ev.Seals()
}

// delegated is whether an event is one only a delegated identity has.
func delegated(ev *keri.Event) bool {
	return ev.Ilk == "dip" || ev.Ilk == "drt" || ev.Delegator != ""
}
