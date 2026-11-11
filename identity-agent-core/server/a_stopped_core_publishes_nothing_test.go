package server

import (
	"os"
	"path/filepath"
	"testing"
)

// After a core is stopped, a core started on another identity's data in the
// same process (the embedded core, switching identities) must not answer for
// the first one's pairwise identifiers.
func TestStoppingACoreForgetsWhatItPublishedForPairwiseIdentifiers(t *testing.T) {
	registerPairwiseKey("EA", "key-a")
	registerPairwiseKEL("EA", []map[string]interface{}{{"t": "icp"}})
	kelCheckCache.Lock()
	kelCheckCache.m["EA"] = kelCheckResult{State: kelUnchecked}
	kelCheckCache.Unlock()

	forgetPublishedPairwise()

	if _, ok := getPairwiseKey("EA"); ok {
		t.Error("did.json is still served for A after the stop")
	}
	if _, ok := getPairwiseKEL("EA"); ok {
		t.Error("the OOBI is still served for A after the stop")
	}
	kelCheckCache.Lock()
	_, cached := kelCheckCache.m["EA"]
	kelCheckCache.Unlock()
	if cached {
		t.Error("a key-check result of the previous core survived the stop")
	}
}

// The real Stop does it, and writes then removes the pid an app ends the core by.
func TestStopForgetsPublishedIdentifiersAndTheProcessFile(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir, Port: 0, EntityType: "individual"})
	if err != nil {
		t.Skipf("server unavailable: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".pid")); err != nil {
		t.Errorf("a running core writes its process id beside .port: %v", err)
	}
	registerPairwiseKey("EB", "key-b")
	s.Stop()
	if _, ok := getPairwiseKey("EB"); ok {
		t.Error("Stop left a published pairwise key")
	}
	if _, err := os.Stat(filepath.Join(dir, ".pid")); err == nil {
		t.Error("Stop left .pid behind")
	}
}
