package drivers

import (
	"encoding/json"
	"fmt"
)

// EventSeal is KERI's event seal: a reference to one event in an identity's
// log, naming which identity, where in the log, and which event exactly.
//
// All three are needed. A seal naming only the identity would approve anything
// that identity ever published, and one naming only the position would be
// satisfied by whatever event later occupied it.
//
// sn is the sequence number as an event writes it, lowercase hex. The fields
// are written in the order the specification lists and never from a Go map,
// which would sort them: the same seal is accepted in the specified order and
// refused in sorted order by an independent implementation.
//
// This is the one writer of a general event seal: a registry anchor, a
// delegation approval and an ownership anchor are all this seal, told apart by
// what is sealed. The owner seal is the same shape and is not yet written
// here: it still has three writers of its own (ownerEventSeal in this package,
// keriengine.OwnerSeal and the server's ownerAnchorSeal), each with its own
// checks, which are to be folded into one.
func EventSeal(identifier, sn, digest string) (json.RawMessage, error) {
	if identifier == "" || sn == "" || digest == "" {
		return nil, fmt.Errorf("an event seal needs an identifier, a sequence number and a "+
			"digest; got %q, %q, %q", identifier, sn, digest)
	}
	return json.RawMessage(fmt.Sprintf(`{"i":%s,"s":%s,"d":%s}`,
		quoteJSON(identifier), quoteJSON(sn), quoteJSON(digest))), nil
}

// quoteJSON renders a string as a JSON string, so a value containing a quote
// or a backslash cannot break out of the seal being assembled.
func quoteJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string does not fail; this keeps the helper total.
		return `""`
	}
	return string(b)
}
