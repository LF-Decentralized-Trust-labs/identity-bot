package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/backup"
	"identity-agent-core/endpoint"
	"identity-agent-core/relay"
	"identity-agent-core/relay/relaytest"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// deterministicRootSeed is a fixed 64-byte seed so a test can assert that the
// derived enrolment key is the same across simulated restarts.
func deterministicRootSeed() []byte {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

// recordedEnrolment writes the record a core makes when it mints a relay
// enrolment identifier at index idx, with a real inception event, so a start
// can reuse it without a KERI engine.
func recordedEnrolment(t *testing.T, dir, file, base string, idx int) storedRelayEnrollment {
	t.Helper()
	seed, err := backup.DerivePairwiseSeed(deterministicRootSeed(), idx, 0)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := backup.DerivePairwiseSeed(deterministicRootSeed(), idx, 1)
	cur, _ := keri.NewSoftwareSigner(seed, true)
	nxt, _ := keri.NewSoftwareSigner(next, true)
	pub, _ := cur.PublicKey()
	npub, _ := nxt.PublicKey()
	nd, _ := keri.NextDigest(npub)
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd},
		Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	var fields map[string]interface{}
	if err := json.Unmarshal(ev, &fields); err != nil {
		t.Fatal(err)
	}
	rec := storedRelayEnrollment{
		BaseURL: base, AID: parsed.Identifier, RelationshipIndex: idx,
		PublicKey: base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)),
		KEL:       []map[string]interface{}{fields},
	}
	if err := saveRelayEnrollment(dir, file, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// relayWorld is a core with a recorded enrolment, pointed at an in-process
// relay of the given mode, with its real router.
func relayWorld(t *testing.T, mode relayproto.Mode) (*CoreServer, *relaytest.Relay, storedRelayEnrollment, context.CancelFunc) {
	t.Helper()
	rl := relaytest.New(mode)
	t.Cleanup(rl.Close)
	dir := t.TempDir()
	if err := secureenclave.StoreRootSeed(dir, deterministicRootSeed()); err != nil {
		t.Fatal(err)
	}
	kind := privateRelay
	t.Setenv("RELAY_BASE_URL", "")
	t.Setenv("PUBLIC_RELAY_BASE_URL", "")
	if mode == relayproto.ModePublic {
		kind = publicRelay
		t.Setenv("PUBLIC_RELAY_BASE_URL", rl.URL())
	} else {
		t.Setenv("RELAY_BASE_URL", rl.URL())
	}
	rec := recordedEnrolment(t, dir, kind.record, rl.URL(), 4)
	ctx, cancel := context.WithCancel(context.Background())
	s := &CoreServer{DataDir: dir, DataStore: testDataStore(t, dir), EndpointService: endpoint.New(nil, 5050), Port: 5050,
		AppCtx: ctx, cancel: cancel, running: true, relayTLS: rl.TLS(), relayClient: rl.Client()}
	if mode == relayproto.ModePublic {
		s.DefaultIngressMode = func(string) IngressMode { return IngressModePublic }
		if err := s.DataStore.SaveSettings(store.SettingsData{PublicRelayName: "acme"}); err != nil {
			t.Fatal(err)
		}
	}
	s.router = s.buildRouter("")
	return s, rl, rec, cancel
}

func testDataStore(t *testing.T, dir string) store.Store {
	t.Helper()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func (s *CoreServer) waitForRelay(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.Lock()
		rm := s.RelayManager
		s.mu.Unlock()
		if rm != nil && rm.URL() != "" {
			return rm.URL()
		}
		if time.Now().After(deadline) {
			t.Fatal("the relay never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func through(t *testing.T, c *http.Client, method, url, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// A private address carries a relationship: a counterparty resolves the
// identity and posts it a message, through the relay to the real router.
func TestAPrivateAddressReachesTheIdentityAgentsArtifactsAndMessages(t *testing.T) {
	s, rl, rec, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	url := s.waitForRelay(t)

	code, body := through(t, rl.Caller(), "GET", url+"/oobi/"+rec.AID, "")
	if code != http.StatusOK || !strings.Contains(body, rec.AID) {
		t.Fatalf("the enrolment identifier's OOBI did not come through the relay: %d %s", code, body)
	}
	// Not a valid envelope, so the handler refuses it, but it is the handler
	// that answers, not the private-address rule.
	code, body = through(t, rl.Caller(), "POST", url+"/didcomm", "{}")
	if strings.Contains(body, "not reachable at a private address") || code == http.StatusNotFound {
		t.Fatalf("a message did not reach the message endpoint through a private address: %d %s", code, body)
	}
}

// A private address reaches only what a relationship needs, by this Identity
// Agent's own rule, whatever the relay passes.
func TestAPrivateAddressReachesNothingElse(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePrivate)
	rl.ClaimMode = relayproto.ModePublic // a relay that passes everything and calls it public
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	url := s.waitForRelay(t)

	for _, path := range []string{"/api/contacts", "/api/identity", "/api/health", "/api/attestation"} {
		code, body := through(t, rl.Caller(), "GET", url+path, "")
		if code != http.StatusNotFound || !strings.Contains(body, "not reachable at a private address") {
			t.Errorf("%s through a private address: %d %s", path, code, body)
		}
	}
}

// What a private address may reach is never more than a stranger may: every
// relationship route is a public route.
func TestEveryRelationshipRouteIsPublic(t *testing.T) {
	for key := range relationshipRoutes {
		if _, ok := publicRoutes[key]; !ok {
			t.Errorf("%s may be reached at a private address but is not a public route", key)
		}
	}
}

// A request through a relay is never the owner, even though it reaches the
// Identity Agent over a connection from this machine: a public address meets
// the gate as a remote caller, so an owner-only route needs a controller's
// signature.
func TestARelayedRequestIsNotTheOwner(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	url := s.waitForRelay(t)

	// The same route, asked from this machine, is the owner's.
	w := &recorder{header: http.Header{}}
	s.router.ServeHTTP(w, local("GET", "/api/contacts", ""))
	if w.code != 0 && w.code != http.StatusOK {
		t.Fatalf("the local owner was refused, so this test proves nothing: %d", w.code)
	}

	code, body := through(t, rl.Caller(), "GET", url+"/api/contacts", "")
	if code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatalf("an owner-only route answered a relayed request with no signature: %d %s", code, body)
	}
}

// recorder is the smallest ResponseWriter, so the local check above does not
// need a test server.
type recorder struct {
	header http.Header
	code   int
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *recorder) WriteHeader(code int)        { r.code = code }

// A dropped session comes back at the same address.
func TestADroppedRelayComesBackAtTheSameAddress(t *testing.T) {
	s, rl, rec, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	first := s.waitForRelay(t)

	rl.Drop(rec.AID)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if code, _ := through(t, rl.Caller(), "GET", first+"/oobi/"+rec.AID, ""); code == http.StatusOK && rl.Connected(rec.AID) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never reconnected")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if again := s.waitForRelay(t); again != first {
		t.Fatalf("the address moved: %s then %s", first, again)
	}
}

// A restarted Identity Agent comes back at the address it held, even from a
// relay that forgot it.
func TestARestartedIdentityAgentKeepsItsAddress(t *testing.T) {
	s, rl, rec, cancel := relayWorld(t, relayproto.ModePrivate)
	go s.startRelay()
	first := s.waitForRelay(t)
	s.Stop()
	cancel()
	rl.Restart()

	stored, found, err := loadRelayEnrollment(s.DataDir, relayEnrollmentFileName)
	if err != nil || !found || len(stored.Allocations) == 0 || stored.Allocations[0].URL != first || stored.Allocations[0].Secret == "" {
		t.Fatalf("the address was not remembered: %+v %v", stored, err)
	}

	ctx, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	again := &CoreServer{DataDir: s.DataDir, DataStore: s.DataStore, EndpointService: endpoint.New(nil, 5050), Port: 5050,
		AppCtx: ctx, cancel: cancel2, running: true, relayTLS: rl.TLS(), relayClient: rl.Client()}
	again.router = again.buildRouter("")
	go again.startRelay()
	defer again.Stop()
	if url := again.waitForRelay(t); url != first {
		t.Fatalf("the address moved across a restart: %s then %s", first, url)
	}
	if stored.AID != rec.AID {
		t.Fatalf("the enrolment identifier changed across a restart")
	}
}

// A recorded enrolment whose key cannot be re-derived from this root seed is
// not used: it would sign as an identifier whose log names another key.
func TestAnEnrolmentFromAnotherRootSeedIsNotReused(t *testing.T) {
	dir := t.TempDir()
	rec := recordedEnrolment(t, dir, relayEnrollmentFileName, "https://relay.example", 4)
	other := deterministicRootSeed()
	other[0] ^= 0xff
	if _, err := reuseRelayEnrolment(other, &rec); err == nil || !strings.Contains(err.Error(), "not the one") {
		t.Fatalf("an enrolment was reused with a key re-derived from a different root seed: %v", err)
	}
	if _, err := reuseRelayEnrolment(deterministicRootSeed(), &rec); err != nil {
		t.Fatalf("the enrolment's own root seed was refused: %v", err)
	}
}

// A public address and the private ones never share an enrolment identifier:
// sharing one would let a relay join the identity's public name to its
// relationships.
func TestPublicAndPrivateEnrolmentsAreSeparate(t *testing.T) {
	if privateRelay.pool == publicRelay.pool || privateRelay.record == publicRelay.record {
		t.Fatal("public and private relays share an enrolment")
	}
}

// The enrolment record round-trips, address included.
func TestRelayEnrollmentRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := storedRelayEnrollment{BaseURL: "https://relay.example", AID: "ERELAYAID", RelationshipIndex: 3,
		PublicKey: "cHVia2V5", Allocations: []relay.Allocation{{Label: "abc", URL: "https://relay.example/abc", Secret: "s"}}}
	if err := saveRelayEnrollment(dir, relayEnrollmentFileName, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := loadRelayEnrollment(dir, relayEnrollmentFileName)
	if err != nil || !found {
		t.Fatalf("saved enrolment did not load back: found=%v err=%v", found, err)
	}
	if got.AID != want.AID || len(got.Allocations) != 1 || got.Allocations[0] != want.Allocations[0] {
		t.Errorf("round-trip mismatch: got %+v", *got)
	}
}

// A missing record is the ordinary first-run case, not an error.
func TestRelayEnrollmentAbsentIsNotAnError(t *testing.T) {
	_, found, err := loadRelayEnrollment(t.TempDir(), relayEnrollmentFileName)
	if err != nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

// startRelay assigns s.RelayManager in its own goroutine while Stop reads it
// under s.mu, so the assignment must hold s.mu too.
func TestRelayManagerAssignmentDoesNotRaceStop(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			s.mu.Lock()
			_ = s.RelayManager
			s.mu.Unlock()
		}
	}()
	go s.startRelay()
	s.waitForRelay(t)
	close(done)
	wg.Wait()
	s.Stop()
}

// A relay that cannot be reached when the Identity Agent starts is tried
// again, so a network that comes back, or a machine that wakes, ends up at its
// address without anybody restarting it.
func TestARelayThatIsDownAtStartIsTriedAgain(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	rl.Down(true)
	go s.startRelay()
	defer s.Stop()
	time.Sleep(200 * time.Millisecond)
	rl.Down(false)
	s.waitForRelay(t)
}

// An allocate request is signed the way a relay checks it: a plain Ed25519
// signature over the canonical body.
func TestARelayRequestIsSignedTheWayARelayChecksIt(t *testing.T) {
	seed, err := backup.DerivePairwiseSeed(deterministicRootSeed(), 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]interface{}{"v": "x", "raid": "EAID"}
	sig, err := (&relayEnrollmentSigner{seed: seed}).SignCanonical("EAID", body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		t.Fatalf("not a plain Ed25519 signature: %q", sig)
	}
	canon, _ := relayproto.CanonicalBody(body)
	if !ed25519.Verify(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), canon, raw) {
		t.Fatal("the signature does not verify over the canonical body")
	}
}

// A private address is a path at the relay, so what this Identity Agent writes
// about itself through one names that path: a did:webs identifier published
// there keeps the path as segments, or a counterparty resolving it would be
// sent to the relay's root, where nothing answers for it.
func TestAnIdentifierPublishedAtAPrivateAddressNamesItsPath(t *testing.T) {
	s, rl, rec, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := s.DataStore.SaveContact(store.ContactRecord{AID: rec.AID, PublicKey: key}); err != nil {
		t.Fatal(err)
	}
	go s.startRelay()
	defer s.Stop()
	url := s.waitForRelay(t)
	label := url[strings.LastIndex(url, "/")+1:]

	code, body := through(t, rl.Caller(), "GET", url+"/"+rec.AID+"/did.json", "")
	if code != http.StatusOK {
		t.Fatalf("did.json through a private address: %d %s", code, body)
	}
	if !strings.Contains(body, ":"+label+":"+rec.AID) {
		t.Fatalf("the identifier does not name the address's path %q: %s", label, body)
	}
}

// A request from this machine carrying only the relay marker is not the
// owner: the marker alone makes a request remote at the gate, whatever the
// relay itself added.
func TestTheRelayMarkerAloneMakesARequestRemote(t *testing.T) {
	r := local("GET", "/api/contacts", "")
	if !isLocalOwnerRequest(r) {
		t.Fatal("a plain local request is not the owner, so this test proves nothing")
	}
	r.Header.Set(relayproto.ViaRelayHeader, "relay")
	if isLocalOwnerRequest(r) {
		t.Fatal("a request carrying the relay marker was taken for the owner")
	}
}

// A private address does not upgrade, even on a path it may reach, and even
// when the relay passes the upgrade on.
func TestAPrivateAddressDoesNotUpgrade(t *testing.T) {
	s, rl, rec, cancel := relayWorld(t, relayproto.ModePrivate)
	rl.ClaimMode = relayproto.ModePublic // a relay that passes upgrades
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	url := s.waitForRelay(t)
	req, _ := http.NewRequest("GET", url+"/oobi/"+rec.AID, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := rl.Caller().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an upgrade on a private address was answered %d", resp.StatusCode)
	}
}
