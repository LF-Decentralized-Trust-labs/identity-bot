package keriengine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
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

// presentationAttributes is the attribute block, in the order it is hashed.
type presentationAttributes struct {
	D              string `json:"d"`
	CredentialSAID string `json:"credential_said"`
	HolderAID      string `json:"holder_aid"`
}

// presentationBody is the presentation, in the order it is hashed.
type presentationBody struct {
	V  string                 `json:"v"`
	D  string                 `json:"d"`
	I  string                 `json:"i"`
	RI string                 `json:"ri"`
	S  string                 `json:"s"`
	A  presentationAttributes `json:"a"`
}

// presentationVersion is what the driver writes, size and all.
//
// The size is zeroes and is never filled in. That is not a conformant version
// string; it is what the existing format carries, and changing it would change
// every presentation identifier. Reproduced deliberately rather than corrected.
const presentationVersion = "ACDC10JSON000000_"

// defaultPresentationSchema is used when a caller names none.
const defaultPresentationSchema = "EpresentationSchema"

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
	if schemaSaid == "" {
		schemaSaid = defaultPresentationSchema
	}

	// The attribute block is hashed first and its identifier embedded, so the
	// presentation's own identifier commits to it. Hashing the whole thing in
	// one pass would leave the block alterable without changing the outer
	// digest in any way a reader could detect.
	attrs := presentationAttributes{CredentialSAID: acdcSaid, HolderAID: holderAid}
	attrSAID, err := saidOfCompact(attrs)
	if err != nil {
		return nil, fmt.Errorf("computing the attribute identifier: %w", err)
	}
	attrs.D = attrSAID

	body := presentationBody{
		V: presentationVersion, I: holderAid, RI: issuerAid, S: schemaSaid, A: attrs,
	}
	presSAID, err := saidOfCompact(body)
	if err != nil {
		return nil, fmt.Errorf("computing the presentation identifier: %w", err)
	}
	body.D = presSAID

	raw, err := compactJSON(body)
	if err != nil {
		return nil, err
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	return &drivers.DriverPresentCredentialResponse{
		PresentationSaid:    presSAID,
		PresentationJsonB64: base64.StdEncoding.EncodeToString(raw),
		PresentationBody:    parsed,
		// The bytes to sign: the identifier itself, as text.
		PresSaidB64: base64.StdEncoding.EncodeToString([]byte(presSAID)),
	}, nil
}

// saidOfCompact computes the Blake3 identifier of a value as it will be
// serialised.
func saidOfCompact(v interface{}) (string, error) {
	raw, err := compactJSON(v)
	if err != nil {
		return "", err
	}
	return keri.Blake3SAID(raw)
}

// compactJSON serialises without spaces and without HTML escaping.
//
// Both matter for the digest. Go escapes <, > and & by default and Python does
// not, so a credential holding any of them would digest differently in the two
// — and a presentation built by one would not verify against the other.
func compactJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a newline, which is not part of what is hashed.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
