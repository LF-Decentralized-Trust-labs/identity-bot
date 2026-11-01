package server

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// The app founds an identity from a recovery phrase and writes each key in
// qb64. A core holding the same phrase's seed must derive the identical
// string, or it treats the key as held somewhere else and can neither sign
// for the identity nor recover it. The strings are the ones in
// backup/identity-key-vectors.json, which the app's key manager is checked
// against too.
func TestTheCoreRecognisesAKeyTheAppDerived(t *testing.T) {
	raw, err := os.ReadFile("../backup/identity-key-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Phrases []struct {
			BIP39SeedHex string `json:"bip39_seed_hex"`
			Keys         []struct {
				Index         int    `json:"index"`
				SeedHex       string `json:"seed_hex"`
				PublicKeyQB64 string `json:"public_key_qb64"`
			} `json:"keys"`
		} `json:"phrases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Phrases) == 0 || len(v.Phrases[0].Keys) < 3 {
		t.Fatalf("the vectors cannot be read: %v", err)
	}
	ph := v.Phrases[0]
	bip39, _ := hex.DecodeString(ph.BIP39SeedHex)

	dir := t.TempDir()
	if err := secureenclave.StoreRootSeed(dir, bip39); err != nil {
		t.Fatal(err)
	}
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, EventHub: NewEventHub()}
	endsItsBackgroundWork(t, s)

	// At each generation the core's own key is the key the app wrote.
	for gen, k := range ph.Keys {
		if err := ds.SaveIdentity(store.IdentityState{AID: "EOURS", PublicKey: k.PublicKeyQB64, KeyGeneration: gen}); err != nil {
			t.Fatal(err)
		}
		seed, err := s.identitySigningSeed()
		if err != nil {
			t.Fatalf("key %d (%s): the core does not recognise the key the app derived: %v", gen, k.PublicKeyQB64, err)
		}
		if hex.EncodeToString(seed) != k.SeedHex {
			t.Fatalf("key %d: the core derives a different seed", gen)
		}
	}

	// And the engine founds and rotates on keys written this way.
	e := keriengine.New()
	icp, err := e.Incept(drivers.InceptionRequest{PublicKey: ph.Keys[0].PublicKeyQB64, NextPublicKey: ph.Keys[1].PublicKeyQB64})
	if err != nil {
		t.Fatalf("founding on the app's keys: %v", err)
	}
	if _, err := e.Rotate(drivers.RotationRequest{Name: icp.AID, NewPublicKey: ph.Keys[1].PublicKeyQB64, NewNextPublicKey: ph.Keys[2].PublicKeyQB64}); err != nil {
		t.Fatalf("rotating to the key founding committed to: %v", err)
	}
	kel, err := e.GetKel(icp.AID)
	if err != nil {
		t.Fatal(err)
	}
	if got := kel.KEL[1]["k"].([]interface{})[0]; got != ph.Keys[1].PublicKeyQB64 {
		t.Fatalf("the rotation names %v, not the app's key %s", got, ph.Keys[1].PublicKeyQB64)
	}
}
