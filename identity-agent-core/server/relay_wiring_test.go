package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"sync"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/endpoint"
	"identity-agent-core/secureenclave"
)

// deterministicRootSeed is a fixed 64-byte seed so a test can assert that the
// derived enrollment key is the same across simulated restarts.
func deterministicRootSeed() []byte {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

// A relay's whole value is a stable address an agent can hand out and expect to
// keep working. The operator maps the enrollment AID to an allocation, so the
// enrollment identity has to survive a restart — reuse the recorded AID, and the
// allocation (and the public URL) stays put. Minting a fresh AID each start,
// which is what the code used to do, re-enrolled every restart and moved the URL.
//
// This proves the recorded enrollment is reused: two independent "starts" reading
// the same on-disk record produce the same AID and the same signing key.
func TestRelayEnrollmentIsReusedAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	rootSeed := deterministicRootSeed()
	if err := secureenclave.StoreRootSeed(dir, rootSeed); err != nil {
		t.Fatal(err)
	}

	const base = "https://relay.example"
	const aid = "ERELAYENROLLMENTAID000000000000000000000001"
	seed, err := backup.DerivePairwiseSeed(rootSeed, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))

	if err := saveRelayEnrollment(dir, storedRelayEnrollment{
		BaseURL:           base,
		AID:               aid,
		RelationshipIndex: 7,
		PublicKey:         pubB64,
	}); err != nil {
		t.Fatal(err)
	}

	// Each call stands in for a fresh process start: load the record from disk,
	// rebuild the config and signer from it.
	restart := func() (string, string) {
		s := &CoreServer{DataDir: dir, EndpointService: endpoint.New(nil, 5050), Port: 5050}
		stored, found, lerr := loadRelayEnrollment(dir)
		if lerr != nil || !found {
			t.Fatalf("recorded enrollment not reloaded: found=%v err=%v", found, lerr)
		}
		cfg, signer, ok := s.reuseRelayEnrollment(base, rootSeed, stored)
		if !ok {
			t.Fatal("reuseRelayEnrollment refused a record it should have accepted")
		}
		sig, serr := signer.SignCanonical(cfg.EnrollmentAID, map[string]interface{}{"probe": "x"})
		if serr != nil {
			t.Fatal(serr)
		}
		return cfg.EnrollmentAID, sig
	}

	aid1, sig1 := restart()
	aid2, sig2 := restart()

	if aid1 != aid {
		t.Errorf("reused AID is %q, want the recorded %q", aid1, aid)
	}
	if aid1 != aid2 {
		t.Errorf("enrollment AID changed across restarts: %q then %q — the relay URL would move", aid1, aid2)
	}
	if sig1 != sig2 {
		t.Error("the enrollment signing key changed across restarts — the operator could not re-authenticate the same allocation")
	}
}

// The enrollment record has to be readable exactly as written, or a restart
// cannot tell which AID it enrolled and mints a new one.
func TestRelayEnrollmentRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := storedRelayEnrollment{
		BaseURL:           "https://relay.example",
		AID:               "ERELAYAID",
		RelationshipIndex: 3,
		PublicKey:         "cHVia2V5",
	}
	if err := saveRelayEnrollment(dir, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := loadRelayEnrollment(dir)
	if err != nil || !found {
		t.Fatalf("saved enrollment did not load back: found=%v err=%v", found, err)
	}
	if got.AID != want.AID || got.BaseURL != want.BaseURL || got.RelationshipIndex != want.RelationshipIndex {
		t.Errorf("round-trip mismatch: got %+v, want %+v", *got, want)
	}
}

// A missing record is the ordinary first-run case, not an error.
func TestRelayEnrollmentAbsentIsNotAnError(t *testing.T) {
	_, found, err := loadRelayEnrollment(t.TempDir())
	if err != nil {
		t.Fatalf("a never-enrolled agent reported an error: %v", err)
	}
	if found {
		t.Error("found a record where none was ever written")
	}
}

// startRelay runs in its own goroutine off Start and assigns s.RelayManager,
// while Stop reads s.RelayManager under s.mu — so the assignment must hold s.mu
// too, or the two race. Run under `go test -race`: with the assignment guarded
// this is clean; unguarded, the detector flags the concurrent access.
//
// Uses the engine-free reuse path (a recorded enrollment) so the test needs no
// KERI engine, and an unreachable operator so the relay's own Start fails fast
// after the assignment under test has already happened.
func TestStartRelayInstallsUnderTheSameLockStopReadsWith(t *testing.T) {
	dir := t.TempDir()
	rootSeed := deterministicRootSeed()
	if err := secureenclave.StoreRootSeed(dir, rootSeed); err != nil {
		t.Fatal(err)
	}
	const base = "http://127.0.0.1:1" // refuses immediately
	seed, err := backup.DerivePairwiseSeed(rootSeed, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if err := saveRelayEnrollment(dir, storedRelayEnrollment{
		BaseURL: base, AID: "ERACEAID", RelationshipIndex: 4, PublicKey: pubB64,
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_BASE_URL", base)

	// The assign in startRelay happens deep inside it, after slow enrollment work,
	// so a one-shot read tends to finish long before the assign and the dynamic
	// detector never sees them concurrently. A reader that SPINS on the same
	// s.mu-guarded read Stop makes, for the whole time startRelay is running,
	// guarantees the read coincides with the assign — an unguarded assign is then
	// flagged, a guarded one is clean. The real Stop is still exercised afterwards.
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		s := &CoreServer{
			DataDir:         dir,
			EndpointService: endpoint.New(nil, 5050),
			Port:            5050,
			AppCtx:          ctx,
			cancel:          cancel,
			running:         true,
		}
		done := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				// Exactly the access Stop makes on s.RelayManager.
				s.mu.Lock()
				_ = s.RelayManager
				s.mu.Unlock()
			}
		}()
		s.startRelay()
		close(done)
		wg.Wait()
		s.Stop()
	}
}
