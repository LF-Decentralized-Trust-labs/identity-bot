// Package presentation is the shape of a credential presentation: the body the
// holder signs the identifier of, how it is built, and how it is read back and
// checked. One place writes it, so the engine that builds a presentation, the
// verifier that reads one, and the app that decides whether to sign one
// (through keymath) agree to the byte.
//
// This shape is OURS rather than a standard one — the field names and the way
// the identifier is computed are a convention of this project, not something a
// stranger's ACDC implementation would produce. It therefore lives here rather
// than in the KERI library, for the same reason the hybrid cipher suite does:
// baking a private convention into a library offered as conformant would make
// it non-conformant for everybody who wanted the standard thing.
package presentation

import (
	"bytes"
	"encoding/json"
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// Attributes is the attribute block, in the order it is hashed.
type Attributes struct {
	D              string `json:"d"`
	CredentialSAID string `json:"credential_said"`
	HolderAID      string `json:"holder_aid"`
}

// Body is the presentation, in the order it is hashed.
type Body struct {
	V  string     `json:"v"`
	D  string     `json:"d"`
	I  string     `json:"i"`
	RI string     `json:"ri"`
	S  string     `json:"s"`
	A  Attributes `json:"a"`
}

// Version is what the driver writes, size and all.
//
// The size is zeroes and is never filled in. That is not a conformant version
// string; it is what the existing format carries, and changing it would change
// every presentation identifier. Reproduced deliberately rather than corrected.
const Version = "ACDC10JSON000000_"

// DefaultSchema is used when a caller names none.
const DefaultSchema = "EpresentationSchema"

// Build makes the presentation of credentialSAID by holder, to be signed by
// the holder, and returns it with its serialisation.
//
// The attribute block is hashed first and its identifier embedded, so the
// presentation's own identifier commits to it. Hashing the whole thing in one
// pass would leave the block alterable without changing the outer digest in
// any way a reader could detect.
func Build(credentialSAID, holder, issuer, schema string) (*Body, []byte, error) {
	if schema == "" {
		schema = DefaultSchema
	}
	attrs := Attributes{CredentialSAID: credentialSAID, HolderAID: holder}
	attrSAID, err := SAIDOf(attrs)
	if err != nil {
		return nil, nil, fmt.Errorf("computing the attribute identifier: %w", err)
	}
	attrs.D = attrSAID
	body := Body{V: Version, I: holder, RI: issuer, S: schema, A: attrs}
	said, err := SAIDOf(body)
	if err != nil {
		return nil, nil, fmt.Errorf("computing the presentation identifier: %w", err)
	}
	body.D = said
	raw, err := Compact(body)
	if err != nil {
		return nil, nil, err
	}
	return &body, raw, nil
}

// Read reads the bytes of a presentation and checks them: they are exactly the
// presentation's one serialisation (no field beyond its own, no other order or
// spacing), and its identifiers are the digests of what they identify.
func Read(raw []byte) (*Body, error) {
	var body Body
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("it is not shaped like a presentation: %w", err)
	}
	if err := body.Check(); err != nil {
		return nil, err
	}
	again, err := Compact(body)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, raw) {
		return nil, fmt.Errorf("it is not the one serialisation of a presentation, so it says " +
			"something other than what its fields say")
	}
	return &body, nil
}

// ReadFields is Read for a presentation already parsed into an object, whose
// serialisation is not at hand.
//
// Going through the struct rather than the map is deliberate: the identifier is
// a digest over the fields in a fixed order, and a map has no order. Anything
// that re-serialised the map directly would compute a digest nobody else does
// and report every genuine presentation as altered.
func ReadFields(fields map[string]interface{}) (*Body, error) {
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	var body Body
	if err := json.Unmarshal(encoded, &body); err != nil {
		return nil, fmt.Errorf("it is not shaped like a presentation: %w", err)
	}
	if err := body.Check(); err != nil {
		return nil, err
	}
	return &body, nil
}

// Check recomputes the identifiers exactly as they were built: the attribute
// block's own first, then the body with its identifier blanked.
func (body *Body) Check() error {
	claimed := body.D
	if claimed == "" {
		return fmt.Errorf("it carries no identifier")
	}
	attrs := body.A
	attrs.D = ""
	attrSAID, err := SAIDOf(attrs)
	if err != nil {
		return err
	}
	if attrSAID != body.A.D {
		return fmt.Errorf("its attributes do not match the identifier " +
			"they carry, so what it says about the credential or the holder has been changed")
	}
	check := *body
	check.D = ""
	recomputed, err := SAIDOf(check)
	if err != nil {
		return err
	}
	if recomputed != claimed {
		return fmt.Errorf("it claims to be %s but its contents derive %s", claimed, recomputed)
	}
	return nil
}

// SAIDOf computes the Blake3 identifier of a value as it will be serialised.
func SAIDOf(v interface{}) (string, error) {
	raw, err := Compact(v)
	if err != nil {
		return "", err
	}
	return keri.Blake3SAID(raw)
}

// Compact serialises without spaces and without HTML escaping.
//
// Both matter for the digest. Go escapes <, > and & by default and Python does
// not, so a credential holding any of them would digest differently in the two
// — and a presentation built by one would not verify against the other.
func Compact(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a newline, which is not part of what is hashed.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
