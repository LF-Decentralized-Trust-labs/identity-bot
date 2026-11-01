package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
)

// An identity whose key this Identity Agent holds rotates, then rotates again
// and signs with the key it rotated to. The record of which generation the key
// is at moves on with each rotation; if it did not, the second rotation would
// be refused as though the key were held elsewhere.
func TestACoreHeldIdentityRotatesAgain(t *testing.T) {
	aMachineThatMayFound(t)
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, EventHub: NewEventHub(),
		KeriDriver: keriengine.New()}
	endsItsBackgroundWork(t, s)
	s.engineSigns()
	root, err := ensureRootSeed(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := func(gen int) string {
		seed, err := backup.DerivePairwiseSeed(root, 0, gen)
		if err != nil {
			t.Fatal(err)
		}
		return iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	post := func(h http.HandlerFunc, path string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		h(rec, ownerRequest(http.MethodPost, path, strings.NewReader(string(b)), s))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := post(s.handleInception, "/api/inception", map[string]any{"public_key": key(0), "next_public_key": key(1)})
	if code != http.StatusCreated {
		t.Fatalf("founding: %d %v", code, out)
	}
	aid := out["aid"].(string)
	for gen := 1; gen <= 2; gen++ {
		code, out = post(s.handleRotation, "/api/rotation",
			map[string]any{"name": aid, "new_public_key": key(gen), "new_next_public_key": key(gen + 1)})
		if code != http.StatusOK {
			t.Fatalf("rotation to generation %d: %d %v", gen, code, out)
		}
		own, _ := ds.GetIdentity()
		if own.KeyGeneration != gen {
			t.Fatalf("after rotating to generation %d the record says %d", gen, own.KeyGeneration)
		}
		if _, err := s.identitySigningSeed(); err != nil {
			t.Fatalf("after rotating to generation %d this Identity Agent does not hold its key: %v", gen, err)
		}
	}
}
