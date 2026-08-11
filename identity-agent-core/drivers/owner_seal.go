package drivers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ownerEventSeal names the owner's inception event.
//
// An event seal, in the field order the specification lists. It was once
// {"i": <owner>, "r": "owner"}, which is not a shape KERI defines: a strict
// reader parses this field as one of a closed set of seals and could not parse
// an inception carrying the old form at all, so an owned identity's whole log
// was unreadable outside this project.
//
// Every identity here is self-addressing, so the identifier IS the digest of
// its inception event — which is what lets the seal name that event using only
// the identifier, and what makes it resolvable by anyone holding the owner's
// log. An identifier of another kind would produce a seal pointing at nothing.
//
// Written as ordered JSON rather than built from a map, because marshalling a
// map sorts the keys and a seal's field order is part of it.
func ownerEventSeal(ownerAID string) (json.RawMessage, error) {
	if ownerAID == "" {
		return nil, fmt.Errorf("an owner seal must name an owner")
	}
	if !strings.HasPrefix(ownerAID, "E") {
		return nil, fmt.Errorf("%q is not a self-addressing identifier, so an owner seal "+
			"naming it would point at no event", ownerAID)
	}
	return json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`, ownerAID, ownerAID)), nil
}
