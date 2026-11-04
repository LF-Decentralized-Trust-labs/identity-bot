package keymath

import (
	"encoding/json"
	"fmt"
	"sort"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/presentation"
)

// What an app checks about a credential, or a presentation of one, before it
// signs for it: read by the engine every core runs, on the app's own machine,
// so a core that hands back a document cannot choose what it says.

// Credential is a credential read the way the engine reads it, its identifiers
// checked as digests of what they identify.
type Credential struct {
	SAID       string          `json:"said"`
	Issuer     string          `json:"issuer"`
	Schema     string          `json:"schema"`
	Registry   string          `json:"registry,omitempty"`
	Recipient  string          `json:"recipient,omitempty"`
	Attributes json.RawMessage `json:"attributes"`
	Edges      json.RawMessage `json:"edges,omitempty"`
	// Fields is every top-level field the credential carries, sorted: whatever
	// it says beyond what the engine reads into the fields above (a rules
	// block, a salt, anything unknown) is named here, so a caller can require
	// that it holds only what it asked for.
	Fields []string `json:"fields"`
}

// CheckCredential reads a credential's bytes: the canonical serialisation, with
// its identifier the digest of the whole. A document with an event type is a
// key event or a registry event, not a credential.
func CheckCredential(raw []byte) (*Credential, error) {
	c, err := keri.VerifyCredential(raw)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("it is not a credential: %w", err)
	}
	if _, isEvent := top["t"]; isEvent {
		return nil, fmt.Errorf("it has an event type, so it is a key event or a registry event, not a credential")
	}
	fields := make([]string, 0, len(top))
	for name := range top {
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return &Credential{SAID: c.SAID, Issuer: c.Issuer, Schema: c.SchemaSAID, Registry: c.Registry,
		Recipient: c.Recipient, Attributes: c.Attributes, Edges: c.Edges, Fields: fields}, nil
}

// Presentation is a presentation read the way the engine reads it.
type Presentation struct {
	SAID       string `json:"said"`
	Credential string `json:"credential"`
	Holder     string `json:"holder"`
	Issuer     string `json:"issuer"`
	Schema     string `json:"schema"`
}

// CheckPresentation reads a presentation's bytes: exactly its one
// serialisation, its identifiers the digests of what they identify. Bytes that
// are a key event, or anything but a presentation, are refused.
func CheckPresentation(raw []byte) (*Presentation, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("it is not a presentation: %w", err)
	}
	if _, isEvent := probe["t"]; isEvent {
		return nil, fmt.Errorf("it has an event type, so it is a key event or a registry event, not a presentation")
	}
	b, err := presentation.Read(raw)
	if err != nil {
		return nil, err
	}
	return &Presentation{SAID: b.D, Credential: b.A.CredentialSAID, Holder: b.I, Issuer: b.RI, Schema: b.S}, nil
}
