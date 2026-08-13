package server

import (
	"crypto/ed25519"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
)

// agentWithDerivedIdentity builds an agent whose identity was created from its
// own root seed, so it can sign as itself.
//
// That is the uncommon case rather than the usual one: an identity founded on a
// computer has keys the owner's device derived and the agent never sees, which
// is why the agent cannot sign as itself there. Tests that need signing use
// this; tests about the ordinary case must not.
func agentWithDerivedIdentity(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{DataDir: dir, DataStore: ds, EventHub: NewEventHub()}

	rootSeed, err := ensureRootSeed(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := ds.SaveIdentity(store.IdentityState{
		AID:             "EOURS",
		PublicKey:       iacrypto.VerkeyQB64(pub),
		DerivationIndex: 0,
		KeyGeneration:   0,
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

// agentWithNoIdentity builds a freshly installed agent: a data store, and
// nothing that says who it is. This is what a computer looks like the first
// time somebody starts it, and the only state in which pairing is possible.
func agentWithNoIdentity(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	return &CoreServer{DataDir: dir, DataStore: ds, EventHub: NewEventHub()}
}

// startedEngine returns a running KERI engine, skipping if none is available.
func startedEngine(t *testing.T) *keriengine.Engine {
	t.Helper()
	eng := keriengine.New()
	if err := eng.Start(); err != nil {
		t.Skipf("KERI engine unavailable: %v", err)
	}
	return eng
}
