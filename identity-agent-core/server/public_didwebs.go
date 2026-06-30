package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"

	"identity-agent-core/asset"

	"github.com/go-chi/chi/v5"
)

// An Org/Identity Agent is a public entity for the AIDs it owns, so it serves their did.json
// DIRECTLY at its public URL — /public/{aid}/did.json, the path the login OOBI + resolvers use.
// Registered before the SPA catch-all so it returns real did.json, not the app shell. The same
// endpoint resolves PAIRWISE AIDs registered during a transaction (mintPairwise / login).
var pairwiseKeys = struct {
	sync.Mutex
	m map[string]string // aid -> base64url Ed25519 pubkey
}{m: map[string]string{}}

func (s *CoreServer) mountPublicDidWebsRoutes(r chi.Router) {
	r.Get("/public/{aid}/did.json", s.handlePublicDidJSON)
	r.Post("/public/_register", s.handleRegisterPairwise)
	r.Post("/_register", s.handleRegisterPairwise)
}

func (s *CoreServer) handleRegisterPairwise(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AID          string `json:"aid"`
		PublicKeyB64 string `json:"public_key_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AID == "" || body.PublicKeyB64 == "" {
		http.Error(w, "aid + public_key_b64 required", http.StatusBadRequest)
		return
	}
	pairwiseKeys.Lock()
	pairwiseKeys.m[body.AID] = body.PublicKeyB64
	pairwiseKeys.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *CoreServer) handlePublicDidJSON(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	pub := s.publicDidWebsPubKey(aid)
	if pub == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/did+json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id": "did:web:" + aid,
		"verificationMethod": []map[string]interface{}{
			{
				"id":           "did:web:" + aid + "#key-1",
				"type":         "Ed25519VerificationKey2020",
				"publicKeyJwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": pub},
			},
		},
	})
}

// publicDidWebsPubKey returns a base64url Ed25519 pubkey for an AID the agent can vouch for: a
// registered pairwise (mintPairwise / login), or one of its own assets (re-derived from the
// signing index).
func (s *CoreServer) publicDidWebsPubKey(aid string) string {
	pairwiseKeys.Lock()
	p, ok := pairwiseKeys.m[aid]
	pairwiseKeys.Unlock()
	if ok {
		return p
	}
	if s.assetHandler != nil {
		for _, a := range s.assetHandler.Store.ListAssets() {
			if a.PairwiseAID == aid && a.SigningIndex != 0 {
				if seed, err := asset.AssetSigningSeed(s.DataDir, a.SigningIndex); err == nil {
					pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
					return base64.RawURLEncoding.EncodeToString(pub)
				}
			}
		}
	}
	return ""
}
