package m63_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/m63"
)

type c2Golden struct {
	HybridSignature struct {
		Message          string `json:"message"`
		CompositeWire    string `json:"composite_wire"`
		CompositeWireLen int    `json:"composite_wire_len"`
		NegativeVectors  struct {
			HybridSigClassicalCorrupt string `json:"hybrid_sig_classical_corrupt"`
			HybridSigPqcCorrupt      string `json:"hybrid_sig_pqc_corrupt"`
		} `json:"negative_vectors"`
	} `json:"hybrid_signature"`
	HybridInception struct {
		Seed int `json:"seed"`
	} `json:"hybrid_inception"`
}

func loadC2Golden(t *testing.T) c2Golden {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("golden_vectors.json"))
	if err != nil {
		data, err = os.ReadFile(filepath.Join("m63", "golden_vectors.json"))
	}
	if err != nil {
		t.Fatalf("read golden_vectors.json: %v", err)
	}
	var g c2Golden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("parse golden_vectors.json: %v", err)
	}
	return g
}

func TestC2HybridSignatureGolden(t *testing.T) {
	golden := loadC2Golden(t)
	if golden.HybridSignature.CompositeWire == "" {
		t.Fatal("hybrid_signature not pinned — run scripts/pin_m63_c2_golden.py")
	}

	res, err := m63.SignHybridMessage()
	if err != nil {
		t.Fatalf("SignHybridMessage: %v", err)
	}
	if res.CompositeWire != golden.HybridSignature.CompositeWire {
		t.Fatal("composite_wire byte mismatch vs keripy golden")
	}
	if len(res.CompositeWire) != golden.HybridSignature.CompositeWireLen {
		t.Fatalf("composite_wire len: got %d want %d", len(res.CompositeWire), golden.HybridSignature.CompositeWireLen)
	}

	mat := m63.SyntheticHybridKeyMaterial(golden.HybridInception.Seed)
	inc, err := m63.BuildHybridInception(mat)
	if err != nil {
		t.Fatalf("BuildHybridInception: %v", err)
	}
	edVK, mldsaVK, err := m63.C2SigningVerkeys()
	if err != nil {
		t.Fatalf("C2SigningVerkeys: %v", err)
	}
	msg := []byte(golden.HybridSignature.Message)
	if !m63.VerifyHybridSignature(msg, golden.HybridSignature.CompositeWire, edVK, mldsaVK, nil) {
		t.Fatal("crypto-only hybrid signature should verify")
	}
	if !m63.IsHybridIdentity(inc.InceptionEvent) {
		t.Fatalf("expected hybrid identity, a=%v", inc.InceptionEvent["a"])
	}
	if m63.SigningKeyCount(inc.InceptionEvent) != 2 {
		t.Fatalf("expected 2 signing keys, got %d", m63.SigningKeyCount(inc.InceptionEvent))
	}
	if !m63.VerifyHybridSignature(msg, golden.HybridSignature.CompositeWire, edVK, mldsaVK, inc.InceptionEvent) {
		t.Fatal("positive hybrid signature should verify")
	}
	neg := golden.HybridSignature.NegativeVectors
	if m63.VerifyHybridSignature(msg, neg.HybridSigClassicalCorrupt, edVK, mldsaVK, inc.InceptionEvent) {
		t.Fatal("classical-corrupt vector should reject")
	}
	if m63.VerifyHybridSignature(msg, neg.HybridSigPqcCorrupt, edVK, mldsaVK, inc.InceptionEvent) {
		t.Fatal("pqc-corrupt vector should reject")
	}
	single := copyMap(inc.InceptionEvent)
	keys, ok := inc.InceptionEvent["k"].([]string)
	if !ok {
		t.Fatalf("unexpected k type: %T", inc.InceptionEvent["k"])
	}
	single["k"] = []string{keys[0]}
	if m63.VerifyHybridSignature(msg, golden.HybridSignature.CompositeWire, edVK, mldsaVK, single) {
		t.Fatal("single-half inception should reject")
	}
}

func copyMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}