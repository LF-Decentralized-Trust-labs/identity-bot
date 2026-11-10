package server

import (
	"context"
	"strings"
	"testing"
)

// With a driver loaded, an entry that carries no credential bytes is refused,
// however well its declared schema, issuer, holder and status match. The
// presenter writes those fields itself. Fails if the declared-field fallback is
// reached while a driver is present.
func TestAnEntryWithNoCredentialBytesIsRefusedWhenADriverIsLoaded(t *testing.T) {
	w := aGateWorldIssuingTo(t, true, true)
	declared := []interface{}{map[string]interface{}{
		"schema_said": w.schema,
		"issuer_aid":  w.issuer,
		"holder_aid":  w.holder,
		"status":      "issued",
	}}
	ok, _, reason := w.s.credentialGate(context.Background(), declared, w.holder, w.schema, w.issuer)
	if ok {
		t.Fatal("an entry with no credential bytes passed the gate on its declared fields")
	}
	if !strings.Contains(reason, "cannot be verified") {
		t.Fatalf("unexpected reason: %q", reason)
	}
	// The same credential presented with its bytes still passes.
	if ok, reason := w.gate(t); !ok {
		t.Fatalf("the genuine credential was refused: %s", reason)
	}
}
