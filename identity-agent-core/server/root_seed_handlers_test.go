package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

func rootSeedServer(t *testing.T) *CoreServer {
	t.Helper()
	return &CoreServer{DataDir: t.TempDir()}
}

func postSeed(s *CoreServer, seedB64 string, remote bool) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"seed_b64": seedB64})
	req := httptest.NewRequest(http.MethodPost, "/api/keystore/root-seed", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	if remote {
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
	}
	w := httptest.NewRecorder()
	s.handleSetRootSeed(w, req)
	return w
}

// The onboarding handoff installs the mnemonic-derived seed exactly once:
// stored, then idempotent for the same seed, refused for a different one.
func TestSetRootSeedLifecycle(t *testing.T) {
	s := rootSeedServer(t)
	seed, err := backup.MnemonicToBIP39Seed(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(seed)

	if w := postSeed(s, b64, false); w.Code != http.StatusCreated {
		t.Fatalf("first handoff: %d %s", w.Code, w.Body)
	}
	stored, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil || !bytes.Equal(stored, seed) {
		t.Fatalf("stored seed must equal the BIP39 seed: %v", err)
	}

	if w := postSeed(s, b64, false); w.Code != http.StatusOK {
		t.Fatalf("same-seed handoff must be idempotent: %d %s", w.Code, w.Body)
	}

	other := make([]byte, 64)
	other[0] = 0xFF
	if w := postSeed(s, base64.StdEncoding.EncodeToString(other), false); w.Code != http.StatusConflict {
		t.Fatalf("different seed must be refused: %d %s", w.Code, w.Body)
	}
	after, _ := secureenclave.LoadRootSeed(s.DataDir)
	if !bytes.Equal(after, seed) {
		t.Fatal("refused handoff must not change the established seed")
	}
}

// Keystore management is local-owner only; a tunneled request never reaches it.
func TestSetRootSeedRemoteDenied(t *testing.T) {
	s := rootSeedServer(t)
	seed := base64.StdEncoding.EncodeToString(make([]byte, 64))
	if w := postSeed(s, seed, true); w.Code != http.StatusForbidden {
		t.Fatalf("forwarded request must be denied: %d", w.Code)
	}
}

func TestSetRootSeedRejectsBadInput(t *testing.T) {
	s := rootSeedServer(t)
	if w := postSeed(s, "not-base64!!", false); w.Code != http.StatusBadRequest {
		t.Fatalf("bad base64: %d", w.Code)
	}
	if w := postSeed(s, base64.StdEncoding.EncodeToString([]byte("short")), false); w.Code != http.StatusBadRequest {
		t.Fatalf("short seed: %d", w.Code)
	}
	if w := postSeed(s, base64.StdEncoding.EncodeToString(make([]byte, 96)), false); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized seed: %d", w.Code)
	}
}

// Status reports establishment without ever returning the seed.
func TestRootSeedStatus(t *testing.T) {
	s := rootSeedServer(t)
	get := func() map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/keystore/root-seed", nil)
		req.RemoteAddr = "127.0.0.1:9999"
		w := httptest.NewRecorder()
		s.handleRootSeedStatus(w, req)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if got := get(); got["established"] != false {
		t.Fatalf("expected not established, got %v", got)
	}
	postSeed(s, base64.StdEncoding.EncodeToString(make([]byte, 64)), false)
	got := get()
	if got["established"] != true {
		t.Fatalf("expected established, got %v", got)
	}
	if _, leaked := got["seed"]; leaked || len(got) != 1 {
		t.Fatalf("status must reveal nothing but establishment: %v", got)
	}
}

// The recovery acceptance: phrase -> BIP39 seed -> handoff on a fresh device
// re-derives the identical HD pairwise key.
func TestPhraseAloneRederivesHDKeys(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed, _ := backup.MnemonicToBIP39Seed(mnemonic, "")
	b64 := base64.StdEncoding.EncodeToString(seed)

	deviceA := rootSeedServer(t)
	postSeed(deviceA, b64, false)
	seedA, _ := secureenclave.LoadRootSeed(deviceA.DataDir)
	keyA, err := backup.DerivePairwiseSeed(seedA, 7, 0)
	if err != nil {
		t.Fatal(err)
	}

	// "Wiped device": a brand-new data dir, only the phrase survives.
	deviceB := rootSeedServer(t)
	postSeed(deviceB, b64, false)
	seedB, _ := secureenclave.LoadRootSeed(deviceB.DataDir)
	keyB, err := backup.DerivePairwiseSeed(seedB, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("the seed phrase alone must re-derive identical HD keys on a fresh device")
	}
}
