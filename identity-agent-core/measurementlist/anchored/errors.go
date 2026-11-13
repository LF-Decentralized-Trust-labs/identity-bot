package anchored

import (
	"encoding/json"
	"errors"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// Refusals. Each is a different thing for a person or an operator to do
// something about, so they are distinct and wrapped rather than collapsed into
// "invalid". Verify refuses the whole bundle on any of them.
var (
	ErrNoPin     = errors.New("this build pins no software publisher, so no list can be accepted")
	ErrMalformed = errors.New("the bundle is not well formed")

	// ErrNotFresh: not enough of the publisher's witnesses answered with a tip
	// this device asked for just now.
	ErrNotFresh = errors.New("not enough of the publisher's witnesses could be asked for the publisher's latest state")
	// ErrWitnessesDisagree: the witnesses' answers do not all name one tip.
	ErrWitnessesDisagree = errors.New("the publisher's witnesses do not agree on the publisher's latest state")
	// ErrBehind: the bundle's history ends before the witnesses' tip, or before
	// what this device already holds. The caller fetches what is missing.
	ErrBehind = errors.New("the bundle's history ends before the publisher's latest state")
	// ErrAhead: the bundle's history goes past what the witnesses answered.
	ErrAhead = errors.New("the bundle's history goes past what the publisher's witnesses hold")
	// ErrDuplicity: the history conflicts with the one this device already holds.
	ErrDuplicity = errors.New("the publisher's history conflicts with the one this device already holds")

	ErrWrongPublisher = errors.New("the bundle is not for the pinned publisher")
	ErrBadHistory     = errors.New("the publisher's key history does not hold up")
	ErrNotWitnessed   = errors.New("an event of the publisher's key history is not witnessed enough")

	ErrForeignSeal = errors.New("the publisher's key history seals something other than its registry's events")
	ErrWithheld    = errors.New("the publisher's key history seals an event the bundle does not hold")
	ErrUnsealed    = errors.New("the bundle holds an event the publisher's key history does not seal")
	ErrBadRegistry = errors.New("the registry is not the pinned backerless registry of the publisher")
	ErrBadTEL      = errors.New("the registry's events do not hold up")
	ErrBadList     = errors.New("the list credential is not the pinned publisher's, under the pinned schema, in the pinned registry")

	ErrNoList = errors.New("the publisher has no list that is issued and not withdrawn")
)

// Duplicity is the evidence for ErrDuplicity: the event this device holds at a
// place and the different one the offered history has there. Both are signed
// messages, so either can be handed to a watcher.
type Duplicity struct {
	SN      int
	Held    string // SAID held
	Offered string // SAID offered
	Message []byte // the offered message
}

func (d *Duplicity) Error() string { return ErrDuplicity.Error() }
func (d *Duplicity) Unwrap() error { return ErrDuplicity }
