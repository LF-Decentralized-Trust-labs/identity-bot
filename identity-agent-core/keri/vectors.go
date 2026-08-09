// Package keri is the Go implementation of the KERI event layer.
//
// It exists so that one implementation serves every platform this product runs
// on. Today there are two — a Python sidecar on computers and a Rust library on
// phones — and nearly every serious defect found in this subsystem came from
// those two disagreeing quietly: events stored in a form the reference
// implementation refuses, identities founded unsigned, key commitments silently
// dropped. Each was invisible until something real was attempted, because a
// second implementation does not announce that it differs.
//
// Go rather than another language for one reason that outweighs the others: the
// Go core is already compiled into the mobile app. A phone cannot spawn a
// helper process, so whatever runs there must be linked in, and this is already
// linked in. Nothing else has to be introduced.
//
// The package is built against fixed vectors rather than against a reading of
// the specification. An identifier IS a digest of its own event, so two
// implementations agree byte for byte or they do not interoperate at all —
// there is no partial credit, and no amount of review substitutes for checking
// the bytes.
package keri

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// VectorFile is the fixed answers every conformant implementation reproduces.
//
// Generated from keripy, which the KERI implementations table lists at 100%
// spec compliance. Read as data, never as code, so the same file can hold this
// implementation and any other to the same answers.
type VectorFile struct {
	Version int    `json:"vector_version"`
	Oracle  string `json:"oracle"`
	Cases   []Case `json:"cases"`
	What    string `json:"what_this_is"`
	How     string `json:"how_to_use"`
}

// Case is one expectation: given this input, exactly these bytes.
type Case struct {
	ID string `json:"id"`
	// Kind selects what is being asserted — an event to build, a property that
	// must hold, or something that must be refused.
	Kind string `json:"kind"`
	// Why this case exists. Carried in the data so a failure explains what it
	// means rather than only what differed.
	Why    string          `json:"why"`
	Input  json.RawMessage `json:"input"`
	Expect Expectation     `json:"expect"`
}

// Expectation is what a conformant implementation must produce.
type Expectation struct {
	// RawB64 is the authoritative serialisation: the bytes a signature covers
	// and the bytes the identifier is a digest of. Everything else here is
	// derived from it or is for humans.
	RawB64 string `json:"raw_b64"`
	SAID   string `json:"said"`
	AID    string `json:"aid"`
	// Refused marks a case that must be rejected. A conformant implementation
	// failing to reject is as wrong as one producing the wrong bytes, and
	// rather more dangerous.
	Refused bool   `json:"refused"`
	Because string `json:"because"`
	// Constants for cases that assert normative code-table values.
	Codes map[string]string `json:"-"`
}

// Raw returns the canonical bytes this case expects.
func (e Expectation) Raw() ([]byte, error) {
	if e.RawB64 == "" {
		return nil, fmt.Errorf("this case states no expected serialisation")
	}
	return base64.StdEncoding.DecodeString(e.RawB64)
}

// LoadVectors reads a vector file.
func LoadVectors(path string) (*VectorFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read the vectors: %w", err)
	}
	var vf VectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		return nil, fmt.Errorf("the vector file is not readable: %w", err)
	}
	if len(vf.Cases) == 0 {
		// An empty file would make every implementation pass, which is the one
		// outcome worse than failing.
		return nil, fmt.Errorf("the vector file holds no cases, so it proves nothing")
	}
	return &vf, nil
}

// ErrNotImplemented marks a case this implementation cannot yet answer.
//
// Distinguished from a wrong answer on purpose. Unimplemented is a statement
// about how far the work has got; a wrong answer is a statement that this
// implementation disagrees with the rest of the world. Reporting them the same
// way would hide the second among the first, which is exactly the mistake this
// package exists to stop making.
var ErrNotImplemented = fmt.Errorf("not implemented yet")
