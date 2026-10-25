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
	"strings"
	"sync"

	"identity-agent-core/asset"
	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// An Org/Identity Agent is a public entity for the AIDs it owns, so it serves their did.json
// DIRECTLY at its public URL — /public/{aid}/did.json, for did:webs resolvers (ADR-024). A sign-in
// never takes its key from here: it comes from the key log the assertion carries. Registered
// before the SPA catch-all so it returns real did.json, not the app shell. The same endpoint
// answers for PAIRWISE AIDs minted here or published to the key registry with their key log.
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
	keyLogs := newKeyLogGate()
	r.Post("/public/_register", keyLogs.guard(s.handleRegisterPairwise))
	r.Post("/_register", keyLogs.guard(s.handleRegisterPairwise))
	r.Post("/public/login/key", keyLogs.guard(s.handleKeyFromKeyLog))
}

// Checking a key log costs this agent time, and these routes are open to
// anybody, so each caller gets a share and only a few checks run at once.
const (
	keyLogChecksPerMinute = 60
	keyLogChecksAtOnce    = 4
)

// keyLogGate bounds the open routes that check a key log: per caller, by the
// rate limiter the attestation route already uses, and in all, by how many
// run at once. A caller over either is told to come back, not queued.
type keyLogGate struct {
	perCaller *attestationRateLimiter
	running   chan struct{}
}

func newKeyLogGate() *keyLogGate {
	return &keyLogGate{
		perCaller: newAttestationRateLimiter(keyLogChecksPerMinute),
		running:   make(chan struct{}, keyLogChecksAtOnce),
	}
}

func (g *keyLogGate) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !g.perCaller.allow(callerIP(r)) {
			http.Error(w, "too many key logs from this address; try again in a minute", http.StatusTooManyRequests)
			return
		}
		select {
		case g.running <- struct{}{}:
			defer func() { <-g.running }()
		default:
			http.Error(w, "this agent is checking as many key logs as it does at once; try again shortly",
				http.StatusServiceUnavailable)
			return
		}
		next(w, r)
	}
}

// maxKeyLogBody bounds a registration or key request: a key log at its
// largest (login.MaxKeyLogBytes) and the few fields around it.
const maxKeyLogBody = login.MaxKeyLogBytes + 4<<10

// The registry is bounded twice, because anybody can mint identities and
// publish them: by how many identities it holds, and by how many bytes their
// logs take in all. Identities already held can always be carried forward.
const (
	maxRegisteredKeys      = 100000
	maxRegisteredKeysBytes = 256 << 20
)

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
// A held log is replaced only by the same identity's log carried further, or
// by a recovery: a rotation that supersedes interaction events made after the
// identity's last establishment event (mayReplace).
//
// Each identity is its own file in one directory, written to a unique
// temporary file, flushed to disk and renamed into place, so one write never
// rewrites the others, two writers never share a temporary name, and a crash
// leaves either the old entry or the new one. A file that cannot be read is
// kept as it is and its identity refused, never quietly treated as absent and
// overwritten.
type keyRegistry struct {
	mu         sync.Mutex
	dir        string // "" keeps them in memory only
	m          map[string]registeredKey
	unreadable map[string]bool
	bytes      int
}

type registeredKey struct {
	KeyLog       string `json:"key_log"`
	PublicKeyB64 string `json:"public_key_b64"`
}

func (k registeredKey) size() int { return len(k.KeyLog) + len(k.PublicKeyB64) }

func (s *CoreServer) keyRegistry() *keyRegistry {
	s.registeredKeysOnce.Do(func() {
		reg := &keyRegistry{m: map[string]registeredKey{}, unreadable: map[string]bool{}}
		if s.DataDir != "" {
			reg.dir = filepath.Join(s.DataDir, "registered_keys")
			reg.load()
		}
		s.registeredKeys = reg
	})
	return s.registeredKeys
}

func (reg *keyRegistry) load() {
	entries, err := os.ReadDir(reg.dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[keys] ERROR: the published keys in %s cannot be listed: %v", reg.dir, err)
		}
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		aid := strings.TrimSuffix(name, ".json")
		b, err := os.ReadFile(filepath.Join(reg.dir, name))
		var k registeredKey
		if err == nil {
			err = json.Unmarshal(b, &k)
		}
		if err != nil || k.KeyLog == "" {
			log.Printf("[keys] ERROR: the published key for %s in %s cannot be read, so it is "+
				"neither answered for nor replaced until somebody looks: %v", aid, reg.dir, err)
			reg.unreadable[aid] = true
			continue
		}
		reg.m[aid] = k
		reg.bytes += k.size()
	}
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
	if reg.unreadable[aid] {
		return http.StatusConflict, fmt.Errorf("the key held for this identity cannot be read, " +
			"and is not replaced until it is")
	}
	held, had := reg.m[aid]
	if had {
		if held == next {
			return http.StatusOK, nil
		}
		if code, err := mayReplace(held.KeyLog, next.KeyLog); err != nil {
			return code, err
		}
	}
	grows := next.size()
	if had {
		grows -= held.size()
	}
	if !had && len(reg.m) >= maxRegisteredKeys {
		return http.StatusInsufficientStorage, fmt.Errorf("this agent holds as many published keys as it keeps")
	}
	if grows > 0 && reg.bytes+grows > maxRegisteredKeysBytes {
		return http.StatusInsufficientStorage, fmt.Errorf("this agent holds as many published key logs as it keeps")
	}
	if reg.dir != "" {
		if err := reg.write(aid, next); err != nil {
			log.Printf("[keys] the key for %s could not be written down: %v", aid, err)
			return http.StatusInternalServerError, fmt.Errorf("the key could not be written down, so it was not accepted")
		}
	}
	reg.m[aid] = next
	reg.bytes += grows
	return http.StatusOK, nil
}

// write puts one identity's entry on disk: a unique temporary file, flushed,
// then renamed over the entry, so it is the old entry or the new one and
// never half of either.
func (reg *keyRegistry) write(aid string, k registeredKey) error {
	if aid == "" || strings.ContainsAny(aid, `/\.`) {
		return fmt.Errorf("%q is not an identifier that can name a file", aid)
	}
	if err := os.MkdirAll(reg.dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(k)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(reg.dir, aid+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(reg.dir, aid+".json")); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// mayReplace allows a log to replace another when it is the same identity's
// log carried further (every event held is in it, in place), or when it
// recovers the identity.
//
// Recovery is KERI's superseding rule. Whoever stole an identity's key can
// sign interaction events with it, but cannot rotate: a rotation must reveal
// the key the last establishment event committed to, which the thief does not
// have. So a log that agrees with the held one up to some point and then
// rotates, where everything the held log has after that point is interaction
// events, is the owner taking the identity back, and it wins. Without this, a
// thief appending one interaction event would hold the identity here for
// ever. A held rotation is never superseded: only an establishment event
// changes who the identity is.
func mayReplace(heldEncoded, nextEncoded string) (int, error) {
	held, err := login.DecodeKeyLog(heldEncoded)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	next, err := login.DecodeKeyLog(nextEncoded)
	if err != nil {
		return http.StatusBadRequest, err
	}
	fork := 0
	for fork < len(held.RawEventsB64) && fork < len(next.RawEventsB64) &&
		held.RawEventsB64[fork] == next.RawEventsB64[fork] {
		fork++
	}
	if fork == len(held.RawEventsB64) {
		return http.StatusOK, nil // the held log, carried further (or the same)
	}
	if fork == 0 {
		return http.StatusConflict, fmt.Errorf("a different key log is already held for this " +
			"identity, and it is not replaced")
	}
	if fork == len(next.RawEventsB64) {
		return http.StatusConflict, fmt.Errorf("a longer key log is already held for this identity, " +
			"and a shorter one does not replace it")
	}
	recovers, err := isEstablishment(next.RawEventsB64[fork])
	if err != nil {
		return http.StatusBadRequest, err
	}
	if !recovers {
		return http.StatusConflict, fmt.Errorf("a different key log is already held for this " +
			"identity, and only a rotation recovering it replaces it")
	}
	for _, raw := range held.RawEventsB64[fork:] {
		est, err := isEstablishment(raw)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		if est {
			return http.StatusConflict, fmt.Errorf("the held key log rotated after the point this " +
				"one leaves it, so this one does not supersede it")
		}
	}
	return http.StatusOK, nil
}

func isEstablishment(rawB64 string) (bool, error) {
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return false, fmt.Errorf("an event of the key log is not readable: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return false, fmt.Errorf("an event of the key log does not parse: %w", err)
	}
	return ev.Establishment(), nil
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
