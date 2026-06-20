package m63_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/m63"
)

type goldenVector struct {
	HybridInception struct {
		Seed                   int    `json:"seed"`
		AID                    string `json:"aid"`
		SAID                   string `json:"said"`
		RawBytesB64            string `json:"raw_bytes_b64"`
		RawBytesB64Len         int    `json:"raw_bytes_b64_len"`
		CipherSuite            string `json:"cipher_suite"`
		SigningKeysInK         int    `json:"signing_keys_in_k"`
		KeyAgreementInAnchor   int    `json:"key_agreement_in_anchor"`
		PreRotationDigestsInN  int    `json:"pre_rotation_digests_in_n"`
	} `json:"hybrid_inception"`
}

func loadGolden(t *testing.T) goldenVector {
	t.Helper()
	path := filepath.Join("golden_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		// fallback when tests run from module root
		data, err = os.ReadFile(filepath.Join("m63", "golden_vectors.json"))
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

func TestCrossEngineByteIdentitySeed0(t *testing.T) {
	golden := loadGolden(t)
	mat := m63.SyntheticHybridKeyMaterial(golden.HybridInception.Seed)
	res, err := m63.BuildHybridInception(mat)
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
		t.Fatalf("keri 1.1.17 inceptive icp: aid must equal said, got aid=%q said=%q", res.AID, res.SAID)
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
	k, _ := ked["k"].([]string)
	if len(k) != golden.HybridInception.SigningKeysInK {
		t.Fatalf("k len: %d", len(k))
	}
	switch a := ked["a"].(type) {
	case []map[string]interface{}:
		if len(a) != 1 || a[0]["ia"] != m63.CipherSuiteIAHybrid1 {
			t.Fatalf("anchor seal: %v", a)
		}
	case []interface{}:
		if len(a) != 1 {
			t.Fatalf("a anchor: %v", ked["a"])
		}
		seal, ok := a[0].(map[string]interface{})
		if !ok || seal["ia"] != m63.CipherSuiteIAHybrid1 {
			t.Fatalf("anchor seal: %v", a[0])
		}
	default:
		t.Fatalf("a anchor: %v", ked["a"])
	}
}

func TestSyntheticHybridInceptionStructure(t *testing.T) {
	mat := m63.SyntheticHybridKeyMaterial(0)
	res, err := m63.BuildHybridInception(mat)
	if err != nil {
		t.Fatalf("BuildHybridInception: %v", err)
	}
	if res.CipherSuite != m63.CipherSuiteIAHybrid1 {
		t.Fatalf("cipher suite: got %q", res.CipherSuite)
	}
	if res.AID == "" || res.SAID == "" {
		t.Fatal("expected non-empty aid and said")
	}
	k, ok := res.InceptionEvent["k"].([]string)
	if !ok || len(k) != 2 {
		t.Fatalf("ked k: %v", res.InceptionEvent["k"])
	}
	if k[0][0:1] != "D" {
		t.Fatalf("Ed25519 key should use D prefix, got %s", k[0][:4])
	}
	if k[1][0:4] != m63.CESRMLDSA65Verkey {
		t.Fatalf("ML-DSA key prefix: %s", k[1][:4])
	}
}