package didcomm

import (
	"encoding/json"
	"testing"
)

// A wire format about to be implemented a second time.
//
// The envelope is produced by Go today and will be produced and read by Rust on
// the client. Two implementations of one format drift — a field name, an
// ordering, a base64 alphabet — and the drift is silent: envelopes simply stop
// opening, with a failure that looks like a wrong key rather than a wrong
// spelling.
//
// The SNP report reader had exactly this problem and it was caught by pinning a
// vector both sides assert. This does the same for the envelope, BEFORE the
// second implementation exists, so the Rust side has something to be correct
// against rather than something to be compared with afterwards.
//
// What is pinned here is the SHAPE: the field names and their nesting, which is
// what a second implementation gets wrong. The ciphertext cannot be pinned —
// every envelope carries fresh ephemeral material by design — so equality of
// output is not the test and never can be.

func TestTheEnvelopeShapeIsWhatTheOtherSideMustProduce(t *testing.T) {
	// Field names as they appear on the wire. A rename on either side breaks
	// every envelope between them.
	env := Envelope{
		Mode:       "authcrypt",
		Ciphertext: "…",
		IV:         "…",
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]interface{}
	if err := json.Unmarshal(body, &shape); err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"mode", "ciphertext", "protected", "recipients", "iv"} {
		if _, ok := shape[field]; !ok {
			t.Errorf("the envelope no longer carries %q — anything written against the "+
				"old shape stops opening", field)
		}
	}
}

func TestTheCarriedMessageShapeIsPinnedToo(t *testing.T) {
	jwm := JWM{
		ID: "1", Type: "t", From: "did:keri:EA", To: []string{"did:keri:EB"},
		CreatedTime: "2026-01-01T00:00:00Z", ExpiresTime: "2026-01-01T00:05:00Z",
		Body: json.RawMessage(`{}`),
	}
	body, err := json.Marshal(jwm)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]interface{}
	if err := json.Unmarshal(body, &shape); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "type", "from", "to", "created_time", "expires_time", "body"} {
		if _, ok := shape[field]; !ok {
			t.Errorf("the carried message no longer has %q", field)
		}
	}
	// `to` is a list even with one recipient. A second implementation that
	// writes a bare string produces something this side cannot read, and the
	// error names the type rather than the field.
	if _, ok := shape["to"].([]interface{}); !ok {
		t.Error("`to` is no longer a list; a single recipient must still be a list of one")
	}
}

// The key-agreement material a second implementation has to produce exactly.
// Both are required — the exchange combines them, so an implementation that
// omits either derives a different content key and every envelope fails to
// open with no indication of which half was missing.
func TestTheKeyAgreementMaterialNamesBothHalves(t *testing.T) {
	body, err := json.Marshal(kaMaterial{EphemeralX: "a", KemCT: "b"})
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]string
	if err := json.Unmarshal(body, &shape); err != nil {
		t.Fatal(err)
	}
	if shape["epk"] == "" {
		t.Error("the ephemeral key is no longer carried as `epk`")
	}
	if shape["kem_ct"] == "" {
		t.Error("the encapsulation is no longer carried as `kem_ct` — an implementation " +
			"that sends only the classical half derives a different key and fails to open " +
			"everything, without saying why")
	}
}
