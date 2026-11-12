package measurementlist

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/update"
)

// Negative vectors: files other implementations can feed their own verifier,
// each with the refusal it must produce. They are reproduced from the fixed
// vector key, so they cannot drift unseen (WRITE_VECTORS=1 rewrites them).
//
// Run against the key in testdata/publisher_key.hex, at time 2026-11-12T12:00Z,
// with a highest-accepted sequence of min_sequence (7 for "old_sequence").

type negativeVector struct {
	File        string `json:"file"`
	Refusal     string `json:"refusal"` // name of the error; "" means it verifies
	MinSequence int64  `json:"min_sequence,omitempty"`
	// AcceptedForIndividual is how many measurements a list that verifies
	// accepts for "individual" at the evaluation time.
	AcceptedForIndividual *int   `json:"accepted_for_individual,omitempty"`
	Note                  string `json:"note"`
}

var refusals = map[string]error{
	"ErrBadSignature": ErrBadSignature,
	"ErrOldList":      ErrOldList,
	"ErrExpired":      ErrExpired,
}

func TestTheNegativeVectorsAreRefusedAsTheirFilesSay(t *testing.T) {
	priv, key := vectorKey("measurement-list-vectors-v1")
	otherPriv, _ := vectorKey("some-other-publisher")

	tampered := sign(t, priv, baseDoc())
	tampered = []byte(strings.Replace(string(tampered), meas(0x11), meas(0x99), 1))

	// Another key: same content, signed by a key that is not pinned.
	anotherKey := sign(t, otherPriv, baseDoc())

	// Missing domain prefix: signed over the canonical bytes alone.
	noPrefix := baseDoc()
	unsigned, _ := json.Marshal(noPrefix)
	canonical, _ := update.CanonicalizeWithoutField(unsigned, "signature")
	noPrefix["signature"] = update.EncodeBase64URL(ed25519.Sign(priv, canonical))
	noPrefixRaw, _ := json.Marshal(noPrefix)

	oldSeq := baseDoc()
	oldSeq["sequence"] = 6

	expired := baseDoc()
	expired["published_at"], expired["expires_at"] = "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z"

	outside := baseDoc()
	e := entry("individual-v19", 0x11)
	e["valid_until"] = "2026-11-10T00:00:00Z" // ended before the evaluation time
	outside["images"] = map[string]any{"individual": []any{e}}

	zero := 0
	vectors := []struct {
		v   negativeVector
		raw []byte
	}{
		{negativeVector{File: "tampered.json", Refusal: "ErrBadSignature", Note: "a measurement changed after signing"}, tampered},
		{negativeVector{File: "another_key.json", Refusal: "ErrBadSignature", Note: "validly signed by a key that is not the pinned one"}, anotherKey},
		{negativeVector{File: "missing_domain_prefix.json", Refusal: "ErrBadSignature", Note: "signed over the canonical bytes without the measurement-list-v1 line"}, noPrefixRaw},
		{negativeVector{File: "old_sequence.json", Refusal: "ErrOldList", MinSequence: 7, Note: "sequence 6 after sequence 7 was accepted"}, sign(t, priv, oldSeq)},
		{negativeVector{File: "expired.json", Refusal: "ErrExpired", Note: "expires_at is before the evaluation time"}, sign(t, priv, expired)},
		{negativeVector{File: "entry_outside_window.json", AcceptedForIndividual: &zero, Note: "the list verifies, but its only entry ended before the evaluation time, so nothing is accepted"}, sign(t, priv, outside)},
	}

	dir := "testdata/negative"
	var manifest []negativeVector
	for _, c := range vectors {
		manifest = append(manifest, c.v)
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	manifestJSON = append(manifestJSON, '\n')
	if os.Getenv("WRITE_VECTORS") != "" {
		os.MkdirAll(dir, 0o755)
		for _, c := range vectors {
			os.WriteFile(filepath.Join(dir, c.v.File), c.raw, 0o644)
		}
		os.WriteFile(filepath.Join(dir, "expectations.json"), manifestJSON, 0o644)
	}

	gotManifest, err := os.ReadFile(filepath.Join(dir, "expectations.json"))
	if err != nil || string(gotManifest) != string(manifestJSON) {
		t.Fatal("testdata/negative/expectations.json is missing or differs; rerun with WRITE_VECTORS=1 only if intended")
	}
	var committed []negativeVector
	if err := json.Unmarshal(gotManifest, &committed); err != nil {
		t.Fatal(err)
	}
	for i, v := range committed {
		raw, err := os.ReadFile(filepath.Join(dir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != string(vectors[i].raw) {
			t.Errorf("%s differs from what the fixed key produces", v.File)
		}
		l, err := Verify(raw, Policy{Key: key, MinSequence: v.MinSequence, Now: now})
		if v.Refusal != "" {
			if want := refusals[v.Refusal]; !errors.Is(err, want) {
				t.Errorf("%s: got %v, want %s", v.File, err, v.Refusal)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", v.File, err)
			continue
		}
		if got := len(l.Measurements("individual")); got != *v.AcceptedForIndividual {
			t.Errorf("%s: %d accepted, want %d", v.File, got, *v.AcceptedForIndividual)
		}
	}
}
