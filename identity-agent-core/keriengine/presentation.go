package keriengine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"identity-agent-core/drivers"

	"identity-agent-core/presentation"
)

// Presenting a credential that is already held.
//
// Issuing a credential says what is true of somebody. Presenting one says "and
// I am that somebody, now, to you" — and the second is what a verifier actually
// needs, because a credential on its own can be replayed by anyone who has a
// copy of it. The presentation names the credential and the holder, is
// self-addressing, and the holder signs its identifier as proof of possession.
// That binds the proof to this presentation rather than to the credential, so
// it cannot be lifted and reused.
//
// This shape is OURS rather than a standard one — the field names and the way
// the identifier is computed are a convention of this project, not something a
// stranger's ACDC implementation would produce. It therefore lives here rather
// than in the KERI library, for the same reason the hybrid cipher suite does:
// baking a private convention into a library offered as conformant would make
// it non-conformant for everybody who wanted the standard thing.
//
// Byte-compatible with the driver it replaces. A presentation built by one and
// verified by the other has to produce the same identifier, or a credential
// presented before an upgrade stops verifying after it.

// PresentCredential builds a presentation of a credential the caller holds.
//
// Returns the bytes the holder must sign — the presentation's identifier, not
// the presentation itself. Signing the identifier is what ties the proof to
// this presentation: the identifier is a digest of the whole body, so a
// signature over it covers everything the presentation says while staying short
// enough to sign on a device that holds the keys.
func (e *Engine) PresentCredential(acdcSaid, holderAid, issuerAid, schemaSaid string) (*drivers.DriverPresentCredentialResponse, error) {
	if acdcSaid == "" {
		return nil, fmt.Errorf("a presentation must name the credential being presented")
	}
	if holderAid == "" {
		return nil, fmt.Errorf("a presentation must name the holder; without one there is " +
			"nobody for the proof of possession to be about")
	}
	body, raw, err := presentation.Build(acdcSaid, holderAid, issuerAid, schemaSaid)
	if err != nil {
		return nil, err
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	presSAID := body.D

	return &drivers.DriverPresentCredentialResponse{
		PresentationSaid:    presSAID,
		PresentationJsonB64: base64.StdEncoding.EncodeToString(raw),
		PresentationBody:    parsed,
		// The bytes to sign: the identifier itself, as text.
		PresSaidB64: base64.StdEncoding.EncodeToString([]byte(presSAID)),
	}, nil
}
