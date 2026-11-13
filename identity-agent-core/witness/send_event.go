package witness

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/store"
)

// ErrNotWitnessing is a witness's answer that it holds no log for the
// identifier and has no relationship that would have it take one: not
// designated, not declared, or the owner's agreement does not cover it. A caller
// that declared the identifier (RequestCover) tells the witness again.
var ErrNotWitnessing = errors.New("not_witnessing")

// ErrNoReceipt is a witness's answer to an event that is not a receipt this
// agent can count: none, not its own, not signed over the event, or at another
// place than the list in force gives it.
var ErrNoReceipt = errors.New("the witness gave no receipt that verifies")

// witnessRefusal is a witness's refusal of a POST, with what it said.
type witnessRefusal struct {
	status int
	body   string
}

func (e *witnessRefusal) Error() string { return fmt.Sprintf("witness POST %d: %s", e.status, e.body) }

// Is says a refusal is ErrNotWitnessing when the witness said it was not
// witnessing, so a caller asks errors.Is and never reads the text.
func (e *witnessRefusal) Is(target error) bool {
	return target == ErrNotWitnessing && strings.Contains(e.body, "not_witnessing")
}

// EventDelivery is what a witness answered to one event of a log.
type EventDelivery struct {
	// Held: the witness took the event and gave no receipt, because it was not
	// yet named a witness of the identifier when the event was made (the log
	// carries on from it). Receipt is empty then.
	Held bool
	// Receipt is the witness's receipt, an indexed signature over the event's
	// bytes whose index is its place in designated; verified.
	Receipt string
}

// SendEventToWitness sends one event of aid's key log to the witness whose keys
// it signs receipts with (witnessKey) and whose routes are under root (the base
// they resolve against, ending in a slash: ProposedWitness.Address), and reads
// what it answers: a receipt that verifies at its place in designated (the
// witnesses in force at the event; nil when the list is not known, and then no
// place is checked), or Held, or an error: ErrNotWitnessing, ErrNoReceipt, or
// whatever stopped the post. It is the one place an event is sent to a witness
// and its answer read, for BringUpToDate and for a caller that sends a log to the
// witnesses of an identifier this agent does not itself own.
func (s *Service) SendEventToWitness(ctx context.Context, root, witnessKey, aid string, e SignedEvent, designated []string) (EventDelivery, error) {
	raw, err := base64.StdEncoding.DecodeString(e.RawBytesB64)
	if err != nil {
		return EventDelivery{}, fmt.Errorf("the event does not decode: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return EventDelivery{}, fmt.Errorf("the event is not readable: %w", err)
	}
	sigs := store.ControllerSignaturesOf(e.Signatures, e.CesrSignature)
	if len(sigs) == 0 {
		return EventDelivery{}, fmt.Errorf("the event is not signed, and a witness cannot verify it")
	}
	url := strings.TrimRight(root, "/") + "/witness/event"
	resp, err := s.PostEvent(s.ownersLocalAllowed(ctx, url), url, eventBody(aid, e.RawBytesB64, sigs))
	if err != nil {
		return EventDelivery{}, err
	}
	if held, _ := resp["held"].(bool); held {
		return EventDelivery{Held: true}, nil
	}
	sig, wit, verr := ReceiptFromResponse(resp, raw, ev.SAID, designated)
	if verr != nil || wit != witnessKey {
		return EventDelivery{}, ErrNoReceipt
	}
	return EventDelivery{Receipt: sig}, nil
}
