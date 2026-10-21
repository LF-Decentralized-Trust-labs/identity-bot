package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	t.Setenv("PUBLIC_URL", "https://agent.example")

	// The assign in startRelay happens deep inside it, after slow enrollment work,
	// so a one-shot read tends to finish long before the assign and the dynamic
	// detector never sees them concurrently. A reader that SPINS on the same
	// s.mu-guarded read Stop makes, for the whole time startRelay is running,
	// guarantees the read coincides with the assign — an unguarded assign is then
	// flagged, a guarded one is clean. The real Stop is still exercised afterwards.
	for i := 0; i < 20; i++ {
		// Bounded: the relay here never answers, and a relay that cannot be
		// reached is retried until the agent stops.
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
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

// A relay is enrolled only once this agent can be fetched from outside, and is
// handed that address: a relay fetches the enrolling identity's key log, and a
// localhost address is refused.
func TestARelayIsEnrolledOnlyOnceThisAgentIsReachable(t *testing.T) {
	var oobis []string
	var mu sync.Mutex
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/url-relay-service.json" {
			_, _ = w.Write([]byte(`{"protocol_version":"1.0"}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		if o, ok := body["oobi"].(string); ok {
			oobis = append(oobis, o)
		}
		mu.Unlock()
		http.Error(w, `{"error":"stop here"}`, http.StatusBadRequest)
	}))
	defer relaySrv.Close()

	dir := t.TempDir()
	rootSeed := deterministicRootSeed()
	if err := secureenclave.StoreRootSeed(dir, rootSeed); err != nil {
		t.Fatal(err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveRelayEnrollment(dir, storedRelayEnrollment{
		BaseURL: relaySrv.URL, AID: "EREACHAID", RelationshipIndex: 4,
		PublicKey: base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)),
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_BASE_URL", relaySrv.URL)
	t.Setenv("PUBLIC_URL", "")
	t.Setenv("TUNNEL_PROVIDER", "none")
	start := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		s := &CoreServer{DataDir: dir, EndpointService: endpoint.New(nil, 5050), Port: 5050,
			AppCtx: ctx, cancel: cancel, running: true}
		s.startRelay()
		s.Stop()
	}

	start()
	mu.Lock()
	if len(oobis) != 0 {
		t.Fatalf("enrolled while only reachable at %v", oobis)
	}
	mu.Unlock()

	t.Setenv("PUBLIC_URL", "https://agent.example")
	start()
	mu.Lock()
	defer mu.Unlock()
	if len(oobis) == 0 || !strings.HasPrefix(oobis[0], "https://agent.example/") {
		t.Fatalf("the relay was not given this agent's public address: %v", oobis)
	}
}

// A relay that cannot be reached when the agent starts is tried again, so a
// network that comes back, or a machine that wakes, ends up at its address
// without anybody restarting it.
func TestARelayThatIsDownAtStartIsTriedAgain(t *testing.T) {
	var mu sync.Mutex
	discoveries, enrolled := 0, false
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/.well-known/url-relay-service.json":
			discoveries++
			if discoveries == 1 {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"protocol_version":"1.0"}`))
		case "/enroll":
			enrolled = true
			http.Error(w, `{"error":"stop here"}`, http.StatusBadRequest)
		}
	}))
	defer relaySrv.Close()

	dir := t.TempDir()
	rootSeed := deterministicRootSeed()
	if err := secureenclave.StoreRootSeed(dir, rootSeed); err != nil {
		t.Fatal(err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveRelayEnrollment(dir, storedRelayEnrollment{
		BaseURL: relaySrv.URL, AID: "ERETRYAID", RelationshipIndex: 4,
		PublicKey: base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)),
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_BASE_URL", relaySrv.URL)
	t.Setenv("PUBLIC_URL", "https://agent.example")
	t.Setenv("TUNNEL_PROVIDER", "none")

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	s := &CoreServer{DataDir: dir, EndpointService: endpoint.New(nil, 5050), Port: 5050,
		AppCtx: ctx, cancel: cancel, running: true}
	go func() {
		for {
			mu.Lock()
			done := enrolled
			mu.Unlock()
			if done || ctx.Err() != nil {
				cancel()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	s.startRelay()
	s.Stop()

	mu.Lock()
	defer mu.Unlock()
	if !enrolled {
		t.Fatalf("the relay was not tried again after it was down (%d discoveries)", discoveries)
	}
}
