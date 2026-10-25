package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/asset"
	"identity-agent-core/login"

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

// fullySignedLogOf is aid's stored key log (signedEventsOf) split into the
// two lists an introduction carries, or ok false when any event lacks its
// bytes or its signature, since a partly signed log proves nothing a peer can
// rely on.
func (s *CoreServer) fullySignedLogOf(aid string) (raws, sigs []string, ok bool) {
	if s.DataStore == nil {
		return nil, nil, false
	}
	events := s.signedEventsOf(aid)
	if len(events) == 0 {
		return nil, nil, false
	}
	for _, ev := range events {
		if ev.RawBytesB64 == "" || ev.CesrSignature == "" {
			return nil, nil, false
		}
		raws = append(raws, ev.RawBytesB64)
		sigs = append(sigs, ev.CesrSignature)
	}
	return raws, sigs, true
}

func registerPairwiseKey(aid, publicKeyB64 string) {
	pairwiseKeys.Lock()
	pairwiseKeys.m[aid] = publicKeyB64
	pairwiseKeys.Unlock()
}

func getPairwiseKey(aid string) (string, bool) {
	pairwiseKeys.Lock()
	defer pairwiseKeys.Unlock()
	k, ok := pairwiseKeys.m[aid]
	return k, ok
}

func (s *CoreServer) mountPublicDidWebsRoutes(r chi.Router) {
	r.Get("/public/{aid}/did.json", s.handlePublicDidJSON)
	r.Post("/public/_register", s.handleRegisterPairwise)
	r.Post("/_register", s.handleRegisterPairwise)
	r.Post("/public/login/key", s.handleKeyFromKeyLog)
}

// maxKeyLogBody bounds a registration or key request. A pairwise identity's
// log is an event or two; this leaves room for a long one and no more.
const maxKeyLogBody = 1 << 20

// maxRegisteredKeys bounds how many identities may publish a key here.
const maxRegisteredKeys = 100000

// A key registry anybody can write to, that cannot be written wrongly.
//
// Publishing here stays unauthenticated, because a counterparty we have never
// met has no way to authenticate before publishing the key that identifies it.
// What it must now bring is its key log: the registration is accepted only when
// the log validates and its inception derives the identifier being registered,
// so only the holder of that identity's key can publish for it. Before, the key
// alone was taken, for any identifier, and replaced whatever was there — so
// publishing a key against an employee's identifier was a sign-in as them.
//
// A registration is never replaced by a different identity's log. A longer log
// of the same identity (a rotation) replaces a shorter one; a shorter one never
// rolls a longer one back. Registrations are written to disk, so a phone that
// registered once keeps working after this agent restarts.
type keyRegistry struct {
	mu   sync.Mutex
	path string // "" keeps them in memory only
	m    map[string]registeredKey
}

type registeredKey struct {
	KeyLog       string `json:"key_log"`
	PublicKeyB64 string `json:"public_key_b64"`
}

func (s *CoreServer) keyRegistry() *keyRegistry {
	s.registeredKeysOnce.Do(func() {
		reg := &keyRegistry{m: map[string]registeredKey{}}
		if s.DataDir != "" {
			reg.path = filepath.Join(s.DataDir, "registered_keys.json")
			if b, err := os.ReadFile(reg.path); err == nil {
				if err := json.Unmarshal(b, &reg.m); err != nil {
					log.Printf("[keys] %s is not readable, so no published key is answered for: %v",
						reg.path, err)
					reg.m = map[string]registeredKey{}
				}
			}
		}
		s.registeredKeys = reg
	})
	return s.registeredKeys
}

func (reg *keyRegistry) get(aid string) (registeredKey, bool) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	k, ok := reg.m[aid]
	return k, ok
}

// put records aid's proved key, or says why it may not replace what is held.
func (reg *keyRegistry) put(aid string, next registeredKey) (int, error) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if held, ok := reg.m[aid]; ok {
		if code, err := mayReplace(held.KeyLog, next.KeyLog); err != nil {
			return code, err
		}
	}
	prev, had := reg.m[aid]
	// Anybody can mint identities and register them, so the registry is
	// bounded: a stranger filling it costs them a refusal, not this agent its
	// disk. Identities already held can always be carried forward.
	if !had && len(reg.m) >= maxRegisteredKeys {
		return http.StatusInsufficientStorage, fmt.Errorf("this agent holds as many published keys as it keeps")
	}
	reg.m[aid] = next
	if reg.path != "" {
		b, _ := json.MarshalIndent(reg.m, "", "  ")
		tmp := reg.path + ".tmp"
		err := os.WriteFile(tmp, b, 0o600)
		if err == nil {
			err = os.Rename(tmp, reg.path)
		}
		if err != nil {
			if had {
				reg.m[aid] = prev
			} else {
				delete(reg.m, aid)
			}
			return http.StatusInternalServerError, fmt.Errorf("the key could not be written down, so it was not accepted")
		}
	}
	return http.StatusOK, nil
}

// mayReplace allows a log to replace another only when it is the same
// identity's log carried further: every event held is in it, in place.
func mayReplace(heldEncoded, nextEncoded string) (int, error) {
	held, err := login.DecodeKeyLog(heldEncoded)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	next, err := login.DecodeKeyLog(nextEncoded)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if len(next.RawEventsB64) < len(held.RawEventsB64) {
		return http.StatusConflict, fmt.Errorf("a longer key log is already held for this identity, " +
			"and a shorter one does not replace it")
	}
	for i, raw := range held.RawEventsB64 {
		if next.RawEventsB64[i] != raw {
			return http.StatusConflict, fmt.Errorf("a different key log is already held for this " +
				"identity, and it is not replaced")
		}
	}
	return http.StatusOK, nil
}

func (s *CoreServer) handleRegisterPairwise(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AID          string `json:"aid"`
		PublicKeyB64 string `json:"public_key_b64"`
		KeyLog       string `json:"key_log"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxKeyLogBody)).Decode(&body); err != nil ||
		body.AID == "" || body.KeyLog == "" {
		http.Error(w, "aid and key_log required: a key is published here only with the key log "+
			"that proves it belongs to the identity", http.StatusBadRequest)
		return
	}
	pub, err := login.KeyFromKeyLog(body.AID, body.KeyLog)
	if err != nil {
		http.Error(w, "refused: "+err.Error(), http.StatusForbidden)
		return
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	if body.PublicKeyB64 != "" && body.PublicKeyB64 != pubB64 {
		http.Error(w, "refused: the key given is not the key this identity's log holds",
			http.StatusForbidden)
		return
	}
	if code, err := s.keyRegistry().put(body.AID, registeredKey{KeyLog: body.KeyLog, PublicKeyB64: pubB64}); err != nil {
		http.Error(w, "refused: "+err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleKeyFromKeyLog answers, for a verifier that cannot check a key log
// itself, what key an identity's log establishes. It is the same check a
// sign-in here runs (login.KeyFromKeyLog), offered so a relying party in
// another language consults this one instead of keeping a second copy of it.
// It fetches nothing and stores nothing.
func (s *CoreServer) handleKeyFromKeyLog(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AID    string `json:"aid"`
		KeyLog string `json:"key_log"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxKeyLogBody)).Decode(&body); err != nil ||
		body.AID == "" || body.KeyLog == "" {
		http.Error(w, "aid and key_log required", http.StatusBadRequest)
		return
	}
	pub, err := login.KeyFromKeyLog(body.AID, body.KeyLog)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"aid":            body.AID,
		"public_key_b64": base64.RawURLEncoding.EncodeToString(pub),
	})
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
// The registry consulted last is written by an unauthenticated endpoint — that
// is deliberate and necessary, because a pairwise counterparty we have never met
// has no way to authenticate before publishing the key that identifies it. Each
// entry is proved by its key log (keyRegistry). What must never follow from it
// is a stranger's claim overriding what we already know.
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

	// Identities this agent minted itself, whose keys it recorded as it made them.
	pairwiseKeys.Lock()
	p := pairwiseKeys.m[aid]
	pairwiseKeys.Unlock()
	if p != "" {
		return p
	}
	// Identities that published here, each proved by its key log.
	if k, ok := s.keyRegistry().get(aid); ok {
		return k.PublicKeyB64
	}
	return ""
}
