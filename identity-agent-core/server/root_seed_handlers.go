package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"identity-agent-core/secureenclave"
)

// One root of trust: the onboarding mnemonic. The client layer (which generates
// and holds the mnemonic) hands its standard BIP39 seed to the local core here,
// once, at identity creation or recovery. Every HD-derived key — pairwise
// contacts, login relationships, asset signing, audit signing, the
// credential-vault key — then derives from the same root the identity itself
// does, so the seed phrase alone recovers everything. The core never sees the
// mnemonic words, only the derived 64-byte seed; the seed is never returned by
// any endpoint.

type rootSeedRequest struct {
	SeedB64 string `json:"seed_b64"`
}

// handleSetRootSeed installs the mnemonic-derived root seed. Local owner only.
// Idempotent for the same seed; a DIFFERENT established seed is refused — the
// HD root of an identity must never silently rotate.
func (s *CoreServer) handleSetRootSeed(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "keystore management is local-owner only", http.StatusForbidden)
		return
	}
	var req rootSeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SeedB64 == "" {
		jsonError(w, "body must be {\"seed_b64\": \"<base64 BIP39 seed>\"}", http.StatusBadRequest)
		return
	}
	seed, err := base64.StdEncoding.DecodeString(req.SeedB64)
	if err != nil {
		jsonError(w, "seed_b64 is not valid base64", http.StatusBadRequest)
		return
	}
	if len(seed) < 32 || len(seed) > 64 {
		jsonError(w, "seed must be 32-64 bytes (the standard BIP39 seed is 64)", http.StatusBadRequest)
		return
	}

	if existing, lerr := secureenclave.LoadRootSeed(s.DataDir); lerr == nil {
		if bytes.Equal(existing, seed) {
			jsonResponse(w, map[string]any{"status": "unchanged"})
			return
		}
		jsonError(w, "a different root seed is already established on this agent — recover with the original seed phrase, or reset the agent's data directory to start over", http.StatusConflict)
		return
	}

	if err := secureenclave.StoreRootSeed(s.DataDir, seed); err != nil {
		jsonError(w, "failed to store root seed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"status": "stored"})
}

// handleRootSeedStatus reports whether a root seed is established (never the
// seed itself). Local owner only. Lets the client decide whether a handoff is
// still needed.
func (s *CoreServer) handleRootSeedStatus(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "keystore management is local-owner only", http.StatusForbidden)
		return
	}
	_, err := secureenclave.LoadRootSeed(s.DataDir)
	jsonResponse(w, map[string]any{"established": err == nil})
}
