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

// KELs of minted pairwise AIDs, so their OOBI (/public/oobi/{aid}) resolves when a peer adds
// us as a contact.
var pairwiseKELs = struct {
	sync.Mutex
	m map[string][]map[string]interface{}
}{m: map[string][]map[string]interface{}{}}

func registerPairwiseKEL(aid string, kel []map[string]interface{}) {
	pairwiseKELs.Lock()
	pairwiseKELs.m[aid] = kel
	pairwiseKELs.Unlock()
}

func getPairwiseKEL(aid string) ([]map[string]interface{}, bool) {
	pairwiseKELs.Lock()
	defer pairwiseKELs.Unlock()
	k, ok := pairwiseKELs.m[aid]
	return k, ok
}

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
// publicDidWebsPubKey resolves the verification key for an AID.
//
// OUR OWN ASSETS ARE ANSWERED FROM OUR OWN RECORDS, ALWAYS, AND FIRST.
//
// The self-registration map below is written by an unauthenticated endpoint —
// that is deliberate and necessary, because a pairwise counterparty we have never
// met has no way to authenticate before publishing the key that identifies it.
// What must never follow from that is a stranger's claim overriding what we
// already know.
//
// Consulting the map first, as this did, meant anyone who could reach the port
// and knew a provisioned agent's AID could publish a key of their own choosing
// against it — and this function feeds signed-request verification, so the next
// step was forging requests as that agent. The strongest authentication path in
// the system rested on a registry anyone could write.
//
// The ordering below is the fix, and it is the whole fix: a key we can derive or
// that was recorded at enrolment is authoritative and is returned without ever
// consulting the map. The map answers only for AIDs we hold no record of, which
// is exactly the case it exists to serve.
func (s *CoreServer) publicDidWebsPubKey(aid string) string {
	if s.assetHandler != nil {
		for _, a := range s.assetHandler.Store.ListAssets() {
			if a.PairwiseAID != aid {
				continue
			}
			// An asset that brought its own key: the public half was recorded at
			// enrolment and the private half never reached us. Authoritative.
			if a.PublicKey != "" {
				return a.PublicKey
			}
			// An asset whose key we derive from the owner's seed. Also authoritative,
			// and cheaper to trust than anything published over the wire.
			if a.SigningIndex != 0 {
				if seed, err := asset.AssetSigningSeed(s.DataDir, a.SigningIndex); err == nil {
					pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
					return base64.RawURLEncoding.EncodeToString(pub)
				}
			}
			// A known asset whose key we cannot resolve is a failure to answer, not
			// an invitation to accept whatever a stranger published for it.
			return ""
		}
	}

	pairwiseKeys.Lock()
	p := pairwiseKeys.m[aid]
	pairwiseKeys.Unlock()
	return p
}
