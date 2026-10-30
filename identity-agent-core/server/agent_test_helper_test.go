package server

import (
	"testing"

	"identity-agent-core/keriengine"
	"identity-agent-core/store"
)

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
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, EventHub: NewEventHub()}
	endsItsBackgroundWork(t, s)
	return s
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
