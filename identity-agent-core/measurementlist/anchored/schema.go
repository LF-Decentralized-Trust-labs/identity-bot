package anchored

import (
	_ "embed"
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// schemaDocument is the JSON Schema of an "accepted launch measurements" list
// credential. It is the document, not a description of it: its $id is its own
// SAID (Blake3-256 over the document with $id blank, CESR code E), so a
// credential naming that SAID names exactly these bytes. A credential under any
// other schema SAID is refused, however well it is anchored.
//
// It lives here because another party needs it to verify a list it receives
// (D22). The checker does not run a JSON Schema validator: the same rules are
// held by measurementlist.ContentOfAttributes and FromContent, and
// testdata/schema_conformance.json is what both the schema's author and any
// other implementation check their reading of the rules against.
//
//go:embed schema/accepted-launch-measurements.json
var schemaDocument []byte

// SchemaDocument returns the schema document (a copy).
func SchemaDocument() []byte { return append([]byte(nil), schemaDocument...) }

// SchemaSAID is the SAID of SchemaDocument, checked against the document
// itself: it is the document's $id, and it is wrong for no build.
func SchemaSAID() (string, error) {
	said, err := keri.VerifySchema(bytesTrimNL(schemaDocument))
	if err != nil {
		return "", fmt.Errorf("the embedded schema does not match its own identifier: %w", err)
	}
	return said, nil
}

func bytesTrimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
