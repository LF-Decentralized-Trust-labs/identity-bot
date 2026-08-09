package keri

import (
	"encoding/json"
	"fmt"
)

// Answer produces this implementation's response to a conformance case.
//
// This is the seam the work happens behind. Each case kind is answered by one
// function; filling one in moves a group of cases from "not implemented" to
// either agreement or a visible disagreement, and nothing in between.
//
// It returns ErrNotImplemented rather than a wrong answer or an empty one. That
// distinction is the whole design of this harness: a missing answer is progress
// not yet made, a wrong answer is a claim that the rest of the world is wrong,
// and a suite that reported them identically would hide the second among the
// first.
func Answer(c Case) ([]byte, error) {
	switch c.Kind {
	case "inception":
		var in InceptionInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not an inception: %w", err)
		}
		return BuildInception(in)
	case "rotation":
		var in RotationInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not a rotation: %w", err)
		}
		return BuildRotation(in)
	case "interaction":
		var in InteractionInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return nil, fmt.Errorf("case input is not an interaction: %w", err)
		}
		return BuildInteraction(in)
	case "constants", "property", "reject":
		// Asserted directly by their own tests rather than by producing bytes.
		return nil, ErrNotImplemented
	default:
		return nil, fmt.Errorf("no answer defined for a %q case", c.Kind)
	}
}

// InceptionInput is what founding an identity is given.
//
// Field names match the vector file, which matches the reference
// implementation's parameters. Named the same on purpose: a translation layer
// between what the vectors say and what this package calls things is somewhere
// for a mismatch to hide.
type InceptionInput struct {
	Keys        []string                 `json:"keys"`
	NextDigests []string                 `json:"next_digests"`
	Witnesses   []string                 `json:"witnesses"`
	Toad        int                      `json:"toad"`
	Isith       string                   `json:"isith"`
	Nsith       string                   `json:"nsith"`
	Data        []map[string]interface{} `json:"data"`
}

// RotationInput is what changing an identity's keys is given.
type RotationInput struct {
	Prefix      string                   `json:"prefix"`
	Keys        []string                 `json:"keys"`
	PriorSAID   string                   `json:"prior_said"`
	SN          int                      `json:"sn"`
	NextDigests []string                 `json:"next_digests"`
	Isith       string                   `json:"isith"`
	Nsith       string                   `json:"nsith"`
	Data        []map[string]interface{} `json:"data"`
}

// InteractionInput is what anchoring something into a key history is given.
type InteractionInput struct {
	Prefix    string `json:"prefix"`
	PriorSAID string `json:"prior_said"`
	SN        int    `json:"sn"`
	// Seals stay as raw bytes. Their field order is part of the event, and any
	// trip through a Go map would sort it alphabetically and change the
	// identifier.
	Data []json.RawMessage `json:"data"`
}

// BuildInception returns the canonical bytes of an inception event.
//
// The identifier is a digest of these bytes, so this function decides what an
// identity IS. Everything else in KERI rests on it.
func BuildInception(in InceptionInput) ([]byte, error) {
	return nil, ErrNotImplemented
}

// BuildRotation returns the canonical bytes of a rotation event.
//
// A rotation carries the key the previous event committed to and chains to that
// event by digest. Both are checked by whoever reads the history, so both are
// places this can differ from the reference without anything local noticing.
func BuildRotation(in RotationInput) ([]byte, error) {
	return nil, ErrNotImplemented
}
