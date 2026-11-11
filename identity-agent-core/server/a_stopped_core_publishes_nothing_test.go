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
	s := &CoreServer{}
	s.registerPairwiseKey("EA", "key-a")
	s.registerPairwiseKEL("EA", []map[string]interface{}{{"t": "icp"}})
	s.cacheKelCheck("EA", kelCheckResult{State: kelUnchecked})

	s.forgetPublishedPairwise()

	if _, ok := s.getPairwiseKey("EA"); ok {
		t.Error("did.json is still served for A after the stop")
	}
	if _, ok := s.getPairwiseKEL("EA"); ok {
		t.Error("the OOBI is still served for A after the stop")
	}
	if _, cached := s.cachedKelCheck("EA"); cached {
		t.Error("a key-check result of the previous core survived the stop")
	}
}

// One identity's pairwise identifiers never reach another core in the same
// process, whether or not the first has been stopped.
func TestTwoCoresInOneProcessDoNotShareAPairwiseIdentifier(t *testing.T) {
	a, b := &CoreServer{DataDir: t.TempDir()}, &CoreServer{DataDir: t.TempDir()}
	a.rememberMintedPairwise("EA", "key-a", []map[string]interface{}{{"t": "icp"}})
	if _, ok := b.getPairwiseKey("EA"); ok {
		t.Error("core B serves a key core A minted")
	}
	if _, ok := b.getPairwiseKEL("EA"); ok {
		t.Error("core B serves an OOBI core A minted")
	}
	b.restoreMintedPairwise()
	if _, ok := b.getPairwiseKey("EA"); ok {
		t.Error("core B read core A's minted identifiers on Start")
	}
}

// A core stopped and started again on the same profile (a phone's OS ends it
// in the background) serves what it minted, and nothing it did not.
func TestARestartedCoreKeepsThePairwiseIdentifiersItMinted(t *testing.T) {
	dir := t.TempDir()
	first := &CoreServer{DataDir: dir}
	first.rememberMintedPairwise("EMinted", "key-m", []map[string]interface{}{{"t": "icp"}})
	first.registerPairwiseKey("EPublishedByOther", "key-x") // not minted here: not kept
	first.forgetPublishedPairwise()
	if _, ok := first.getPairwiseKey("EMinted"); ok {
		t.Fatal("a stopped core still serves it")
	}

	second := &CoreServer{DataDir: dir}
	second.restoreMintedPairwise()
	if k, ok := second.getPairwiseKey("EMinted"); !ok || k != "key-m" {
		t.Errorf("the restarted core lost the key it minted: %q %v", k, ok)
	}
	if _, ok := second.getPairwiseKEL("EMinted"); !ok {
		t.Error("the restarted core lost the OOBI of what it minted")
	}
	if _, ok := second.getPairwiseKey("EPublishedByOther"); ok {
		t.Error("a key someone else published came back after a restart")
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
	s.registerPairwiseKey("EB", "key-b")
	s.Stop()
	if _, ok := s.getPairwiseKey("EB"); ok {
		t.Error("Stop left a published pairwise key")
	}
	if _, err := os.Stat(filepath.Join(dir, ".pid")); err == nil {
		t.Error("Stop left .pid behind")
	}
}
