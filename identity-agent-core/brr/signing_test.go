package brr_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"identity-agent-core/brr"
)

// The registry checks an issuer's requests over the one signing form every
// service-provider request uses (ADR-049), so the client signs exactly that:
// string fields only, the sequence number as a decimal string, and the
// registry prefix from the path included so an event cannot be replayed into
// another registry.
func TestRegistryRequestsAreSignedInTheOneForm(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var enrol, event map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("%s: a field is not a string: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/registry/enroll" {
			enrol = body
		} else {
			event = body
		}
	}))
	defer ts.Close()

	c := brr.NewClient(ts.URL, priv)
	if err := c.Enroll("EREG"); err != nil {
		t.Fatal(err)
	}
	if err := c.PushBlindedEvent("EREG", "blind-1", "rev", 7); err != nil {
		t.Fatal(err)
	}

	check := func(name string, fields map[string]any, sigB64 string) {
		t.Helper()
		body, err := relayproto.CanonicalBody(fields)
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := base64.RawURLEncoding.DecodeString(sigB64)
		if !ed25519.Verify(pub, body, sig) {
			t.Fatalf("%s is not signed over %s", name, body)
		}
	}
	check("the enrolment", map[string]any{"registry_prefix": "EREG", "issuer_aid": enrol["issuer_aid"],
		"issuer_public_key_b64": enrol["issuer_public_key_b64"]}, enrol["signature"])
	if event["sequence_number"] != "7" {
		t.Fatalf("sequence_number is %q, want the decimal string \"7\"", event["sequence_number"])
	}
	check("the event", map[string]any{"registry_prefix": "EREG", "blinded_id": "blind-1", "event_type": "rev",
		"sequence_number": "7"}, event["signature"])
}
