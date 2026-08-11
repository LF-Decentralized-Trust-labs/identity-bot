package iacrypto_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/iacrypto"
)

type goldenVector struct {
	HybridInception struct {
		Seed                  int    `json:"seed"`
		AID                   string `json:"aid"`
		SAID                  string `json:"said"`
		RawBytesB64           string `json:"raw_bytes_b64"`
		RawBytesB64Len        int    `json:"raw_bytes_b64_len"`
		CipherSuite           string `json:"cipher_suite"`
		SigningKeysInK        int    `json:"signing_keys_in_k"`
		KeyAgreementInAnchor  int    `json:"key_agreement_in_anchor"`
		PreRotationDigestsInN int    `json:"pre_rotation_digests_in_n"`
	} `json:"hybrid_inception"`
}

func loadGolden(t *testing.T) goldenVector {
	t.Helper()
	path := filepath.Join("golden_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		// fallback when tests run from module root
		data, err = os.ReadFile(filepath.Join("iacrypto", "golden_vectors.json"))
	}
	if err != nil {
		t.Fatalf("read golden_vectors.json: %v", err)
	}
	var g goldenVector
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("parse golden_vectors.json: %v", err)
	}
	return g
}

// The recorded bytes are a tripwire, not a conformance check.
//
// The vector is this implementation's own output, so it proves the bytes have
// not moved unnoticed — nothing more. It was previously named as though it
// compared against another engine, which is worth being exact about: no other
// engine implements this hybrid suite, so no such comparison exists to be run,
// and a name implying one invites the reader to trust it for something it never
// did. When the pre-rotation digest was wrong, this test agreed with it.
func TestTheRecordedInceptionBytesHaveNotChanged(t *testing.T) {
	golden := loadGolden(t)
	mat := iacrypto.SyntheticHybridKeyMaterial(golden.HybridInception.Seed)
	res, err := iacrypto.BuildHybridInception(mat)
	if err != nil {
		t.Fatalf("BuildHybridInception: %v", err)
	}
	if res.AID != golden.HybridInception.AID {
		t.Fatalf("aid: got %q want %q", res.AID, golden.HybridInception.AID)
	}
	if res.SAID != golden.HybridInception.SAID {
		t.Fatalf("said: got %q want %q", res.SAID, golden.HybridInception.SAID)
	}
	if res.AID != res.SAID {
		t.Fatalf("an inception identifier IS its own digest, so these must match: aid=%q said=%q", res.AID, res.SAID)
	}
	if len(res.RawBytesB64) != golden.HybridInception.RawBytesB64Len {
		t.Fatalf("raw_bytes_b64 len: got %d want %d", len(res.RawBytesB64), golden.HybridInception.RawBytesB64Len)
	}
	if golden.HybridInception.RawBytesB64 != "" && res.RawBytesB64 != golden.HybridInception.RawBytesB64 {
		t.Fatal("raw_bytes_b64: byte mismatch vs keripy golden vector")
	}
	ked := res.InceptionEvent
	if ked["cs"] != nil {
		t.Fatal("top-level cs must not be present (KERI-conformant)")
	}
	if ked["ka"] != nil {
		t.Fatal("top-level ka must not be present (KERI-conformant)")
	}
	k := stringSlice(ked["k"])
	if len(k) != golden.HybridInception.SigningKeysInK {
		t.Fatalf("k len: %d", len(k))
	}
	switch a := ked["a"].(type) {
	case []map[string]interface{}:
		if len(a) != 1 || a[0]["ia"] != iacrypto.CipherSuiteIAHybrid1 {
			t.Fatalf("anchor seal: %v", a)
		}
	case []interface{}:
		if len(a) != 1 {
			t.Fatalf("a anchor: %v", ked["a"])
		}
		seal, ok := a[0].(map[string]interface{})
		if !ok || seal["ia"] != iacrypto.CipherSuiteIAHybrid1 {
			t.Fatalf("anchor seal: %v", a[0])
		}
	default:
		t.Fatalf("a anchor: %v", ked["a"])
	}
}

func TestSyntheticHybridInceptionStructure(t *testing.T) {
	mat := iacrypto.SyntheticHybridKeyMaterial(0)
	res, err := iacrypto.BuildHybridInception(mat)
	if err != nil {
		t.Fatalf("BuildHybridInception: %v", err)
	}
	if res.CipherSuite != iacrypto.CipherSuiteIAHybrid1 {
		t.Fatalf("cipher suite: got %q", res.CipherSuite)
	}
	if res.AID == "" || res.SAID == "" {
		t.Fatal("expected non-empty aid and said")
	}
	k := stringSlice(res.InceptionEvent["k"])
	if len(k) != 2 {
		t.Fatalf("ked k: %v", res.InceptionEvent["k"])
	}
	if k[0][0:1] != "D" {
		t.Fatalf("Ed25519 key should use D prefix, got %s", k[0][:4])
	}
	if k[1][0:4] != iacrypto.CESRMLDSA65Verkey {
		t.Fatalf("ML-DSA key prefix: %s", k[1][:4])
	}
}

// stringSlice reads a string array from a decoded event field, which may be
// []string or []interface{} depending on whether the event was built in memory
// or round-tripped through JSON. Production code already tolerates both — see
// SigningKeyCount — so a test that insists on one is asserting an implementation
// detail rather than a property of the event.
func stringSlice(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}
