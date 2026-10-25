package authorisation

import (
	"encoding/json"
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// RestsOn is what a credential says authorised it.
type RestsOn struct {
	// Grant is the credential its authorised_by edge names: the Controller
	// Grant of the machine whose request it was issued on. Empty where the
	// credential has no such edge.
	Grant string
	// GrantSchema is the schema that edge says the named credential has.
	GrantSchema string
	// OwnerSigned is a credential issued on a request the owner signed.
	OwnerSigned bool
}

// WhatItRestsOn reads what a credential that verified rests on. It is the one
// reading of it: the check of a machine's request, the export that gathers
// everything a conversation rests on, and the verifier that checks it again
// offline all read it here, so none of them can follow an edge the others do
// not see.
func WhatItRestsOn(c *keri.Credential) (RestsOn, error) {
	var r RestsOn
	if len(c.Edges) > 0 {
		var edges map[string]json.RawMessage
		if err := json.Unmarshal(c.Edges, &edges); err != nil {
			return r, fmt.Errorf("the edges are unreadable: %w", err)
		}
		if raw, ok := edges["authorised_by"]; ok {
			var edge struct {
				N string `json:"n"`
				S string `json:"s"`
			}
			if err := json.Unmarshal(raw, &edge); err != nil {
				return r, fmt.Errorf("the edge is unreadable: %w", err)
			}
			r.Grant, r.GrantSchema = edge.N, edge.S
		}
	}
	if len(c.Attributes) > 0 {
		var a struct {
			Request *struct {
				Kind string `json:"kind"`
			} `json:"request"`
		}
		if err := json.Unmarshal(c.Attributes, &a); err != nil {
			return r, fmt.Errorf("the attributes are unreadable: %w", err)
		}
		r.OwnerSigned = a.Request != nil && a.Request.Kind == "owner"
	}
	return r, nil
}
