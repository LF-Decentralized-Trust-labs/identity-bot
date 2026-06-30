package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"sync"

	"identity-agent-core/asset"

	"github.com/go-chi/chi/v5"
)

// Local-only dev relay (gated by IA_DEV_RELAY=1). Lets a local login round-trip resolve
// pairwise keys without the production relay: an agent registers its pairwise AID -> pubkey
// here, and the did.json is served at the exact path the login resolver fetches
// (/public/{aid}/did.json). NOT for production — a stand-in for the M35 relay in local tests.
var devRelayStore = struct {
	sync.Mutex
	m map[string]string // aid -> base64url Ed25519 pubkey
}{m: map[string]string{}}

// DevRelayEnabled reports whether the local dev relay is on (IA_DEV_RELAY=1).
func DevRelayEnabled() bool { return os.Getenv("IA_DEV_RELAY") == "1" }

// mountDevRelayRoutes registers the dev-relay endpoints. Call only when DevRelayEnabled(),
// and BEFORE the SPA catch-all so /public/{aid}/did.json resolves to real did.json.
func (s *CoreServer) mountDevRelayRoutes(r chi.Router) {
	r.Post("/public/_dev/register", s.handleDevRegister)
	r.Post("/_dev/register", s.handleDevRegister) // alias if a relay base omits /public
	// registerPairwiseOnDevRelay uses /_register when the relay base is not localhost.
	r.Post("/public/_register", s.handleDevRegister)
	r.Post("/_register", s.handleDevRegister)
	r.Get("/public/{aid}/did.json", s.handleDevDidJSON)
}

func (s *CoreServer) handleDevRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AID          string `json:"aid"`
		PublicKeyB64 string `json:"public_key_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AID == "" || body.PublicKeyB64 == "" {
		http.Error(w, "aid + public_key_b64 required", http.StatusBadRequest)
		return
	}
	devRelayStore.Lock()
	devRelayStore.m[body.AID] = body.PublicKeyB64
	devRelayStore.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleDevDidJSON serves a minimal did.json for an AID resolvable by the dev relay:
// a registered pairwise AID, or a known asset (pubkey re-derived from its signing index).
func (s *CoreServer) handleDevDidJSON(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	pub := s.devRelayPubKey(aid)
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

// devRelayPubKey returns a base64url Ed25519 pubkey for an AID: a dev-registered pairwise,
// or a known asset (re-derived from its signing index — same key its KEL was inceptioned with).
func (s *CoreServer) devRelayPubKey(aid string) string {
	devRelayStore.Lock()
	p, ok := devRelayStore.m[aid]
	devRelayStore.Unlock()
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
