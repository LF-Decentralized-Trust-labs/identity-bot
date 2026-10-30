package server

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"identity-agent-core/activitylog"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/keriengine"
	"identity-agent-core/login"
	"identity-agent-core/store"
	"identity-agent-core/vault"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// Fixtures for the tests of the core and of the add-ons built in this module.
//
// They are written here, outside any _test.go file, because the add-ons' tests
// live in the add-ons' own packages and use the same worlds the core's tests
// do: an organisation founded as startup finds it, a controller paired and
// granted, a request signed as a machine signs it. A _test.go file is
// compiled only into this package's own tests, so a fixture kept in one could
// only be copied, never shared. The add-ons reach these through
// internal/addonhost; nothing in this module's programs calls them, so they
// are not linked into any binary.

func grantFor(n byte, grade ControllerGrade) ControllerGrant {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = n + byte(i)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return ControllerGrant{
		ControllerAID: iacrypto.NonTransferableAIDQB64(pub),
		PublicKey:     iacrypto.VerkeyQB64(pub),
		Label:         "the laptop in the study",
		Grade:         grade,
	}
}

// pairMachine asks, signed by the owner, for machine g to be granted.
func (e *elsewhere) pairMachine(t coretypes.TB, g ControllerGrant) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"controller_aid":"` + g.ControllerAID + `","public_key":"` + g.PublicKey + `","label":"` + g.Label + `","grade":"` + string(g.Grade) + `"}`
	rec := httptest.NewRecorder()
	e.s.router.ServeHTTP(rec, signedFor(t, e.s.thisIdentityAgentsIdentifier(), "POST", "/api/controllers", body, testOwnerSeed(), time.Now()))
	return rec
}

// waiting is what waits for the device, of the kinds it is asked to sign.
func waiting(t coretypes.TB, s *CoreServer) []store.SigningRequest {
	t.Helper()
	all, err := s.DataStore.GetPendingSigningRequests()
	if err != nil {
		t.Fatal(err)
	}
	var out []store.SigningRequest
	for _, r := range all {
		if isGrantKind(r.Kind) && r.Status == SigningStatusPending {
			out = append(out, r)
		}
	}
	return out
}

func fulfil(t coretypes.TB, s *CoreServer, req store.SigningRequest, seed []byte) *httptest.ResponseRecorder {
	t.Helper()
	return fulfilWith(t, s, req.ID, signWith(req, seed))
}

// checkAsTheDevice is what the device's own core says of a request, from
// what the queue carries for it.
func checkAsTheDevice(t coretypes.TB, s *CoreServer, req store.SigningRequest) (map[string]interface{}, error) {
	t.Helper()
	parts := s.queuedParts(req.ID)
	shown, err := s.whatIsToBeSigned(req.PayloadB64, parts)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(shown)
	var out map[string]interface{}
	json.Unmarshal(raw, &out)
	return out, nil
}

func keyLogVerifies(t coretypes.TB, s *CoreServer) {
	t.Helper()
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	in := drivers.ValidateKELInput{AID: owner.AID}
	for _, ev := range events {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		in.RawEvents = append(in.RawEvents, raw)
		in.CesrSignatures = append(in.CesrSignatures, ev.CesrSignature)
	}
	if res, err := drivers.ValidateKELFromBytes(in); err != nil || !res.KelVerified {
		t.Fatalf("the key log does not verify: %v %+v", err, res)
	}
}

// withdrawIt signs the one revocation that waits, of a grant signed and not
// wanted, and checks that grant is revoked.
func withdrawIt(t coretypes.TB, e *elsewhere) {
	t.Helper()
	reqs := waiting(t, e.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindRevocation {
		t.Fatalf("no withdrawal waits: %+v", reqs)
	}
	body, _, _ := e.s.DataStore.GetPendingIssuance(reqs[0].ID)
	var p pendingIssuance
	json.Unmarshal([]byte(body), &p)
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("withdrawing: %d %s", rec.Code, rec.Body.String())
	}
	if c, _ := e.s.DataStore.GetCredential(p.Revokes); c == nil || c.Status != "revoked" {
		t.Fatalf("the grant signed and not wanted is not revoked: %+v", c)
	}
}

// elsewhere is an organisation whose key is held on another device: seed is
// the key that device holds.
type elsewhere struct {
	s    *CoreServer
	seed []byte
	// earlier are AI agents made while the key was here, whose grants are
	// gone, as before every AI agent was given one: by name, their ids.
	earlier map[string]string
}

// moveTheKeyElsewhere makes s's key unreadable here, as it is where the device
// that holds it is another one, and returns the key that device holds.
func moveTheKeyElsewhere(t coretypes.TB, s *CoreServer, earlier map[string]string) *elsewhere {
	t.Helper()
	seed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := s.DataStore.GetIdentity()
	owner.DerivationIndex += 1000
	if err := s.DataStore.SaveIdentity(*owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.identitySigningSeed(); err == nil {
		t.Fatal("the key still reads as held here")
	}
	return &elsewhere{s: s, seed: seed, earlier: earlier}
}

func refusedFor(t coretypes.TB, s *CoreServer, n store.Notification, why string) {
	t.Helper()
	_, _, err := s.provedSender(n)
	if err == nil {
		t.Fatalf("a message was taken as proved; want it refused because %q", why)
	}
	if !strings.Contains(err.Error(), why) {
		t.Fatalf("refused for the wrong reason: %v; want %q", err, why)
	}
}

// writeCounting is the engine with every call that makes an identity counted.
type writeCounting struct {
	drivers.KeriEngine
	writes int
}

func everyPublicRoute() map[string]string {
	return everyEntry(publicRoutes, func(a Addon) map[string]string { return a.PublicRoutes })
}

func everySessionForbidden() map[string]string {
	return everyEntry(sessionForbidden, func(a Addon) map[string]string { return a.SessionForbidden })
}

// agentWithDerivedIdentity builds an agent whose identity was created from its
// own root seed, so it can sign as itself.
//
// That is the uncommon case rather than the usual one: an identity founded on a
// computer has keys the owner's device derived and the agent never sees, which
// is why the agent cannot sign as itself there. Tests that need signing use
// this; tests about the ordinary case must not.
func agentWithDerivedIdentity(t coretypes.TB) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, EventHub: NewEventHub()}
	endsItsBackgroundWork(t, s)

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

// signsWithSeeds has an engine built for a test sign each event it appends
// with the seed whose key the identity holds.
func signsWithSeeds(e interface {
	SetEventSignature(func(aid, key string, raw []byte) (string, error))
}, seeds ...[]byte) {
	byKey := map[string][]byte{}
	for _, seed := range seeds {
		byKey[iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))] = seed
	}
	e.SetEventSignature(func(aid, key string, raw []byte) (string, error) {
		seed, ok := byKey[key]
		if !ok {
			return "", fmt.Errorf("no key %s", key)
		}
		return signEventBytes(raw, seed)
	})
}

// talkSigner is the founder: the owner the test organisation names
// (sealTestOwner), and its one signer on the roster.
const talkSigner = "EOWNERTESTAID"

// controllerWorld is an organisation with a signer on its roster and a
// controller paired to it and granted, served over HTTP as it is in
// production, with its activity log open.
type controllerWorld struct {
	s       *CoreServer
	srv     *httptest.Server
	ctlAID  string
	ctlSeed []byte
}

func newControllerWorld(t coretypes.TB) *controllerWorld {
	t.Helper()
	s := orgWorld(t)
	if err := s.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	s.logForTest(t, s.DataDir)
	w := &controllerWorld{s: s}
	// The founder: the owner the organisation names, and its one signer on
	// the roster, as founding makes them.
	w.ctlAID, w.ctlSeed = anAuthorisedMachine(t, s, GradeEnrolled)
	if err := s.assetHandler.Store.UpsertEmployee(asset.Employee{
		PairwiseAID: talkSigner, Name: "Alex", Role: "Owner", Status: "active", IsSigner: true, VouchSig: "0Bvouch",
	}); err != nil {
		t.Fatal(err)
	}
	// Granted as a real one is: anchored. Its signer is settled at first use.
	g, _, _ := s.controllers().Get(w.ctlAID)
	if _, err := s.grantController(g, time.Now().UTC(), coretypes.Authority{}); err != nil {
		t.Fatalf("anchoring the controller's grant: %v", err)
	}
	// The sealed transport replays what it opens through the server's own
	// router, as it does in production.
	s.router = s.buildRouter("")
	w.srv = httptest.NewServer(s.router)
	t.Cleanup(w.srv.Close)
	t.Setenv("PUBLIC_URL", w.srv.URL)
	return w
}

// grantWorld is an organisation that holds its own key, founded and reloaded
// into the engine the way startup reloads it, with its founding event signed and
// stored, and an AI agent delegated from it. Nothing is faked: the grant is
// issued, signed, verified and revoked by the engine that ships.
func grantWorld(t coretypes.TB) (*CoreServer, *asset.Asset) {
	t.Helper()
	s := agentWithDerivedIdentity(t) // the organisation's key is derivable here
	return foundedWith(t, s, nil, 0)
}

func newAuthTestServer(t coretypes.TB) *CoreServer {
	t.Helper()
	return &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
}

// remote builds a request that did not originate on this machine — the shape a
// tunnelled or forwarded caller has.
func remote(method, path string, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.9:51000"
	return r
}

// local builds a request from the machine the agent runs on.
func local(method, path string, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:51000"
	r.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	return r
}

// The replay cache is process-wide, which is right in production and awkward
// across tests: two tests signing the same request at the same second produce
// the same signature, and the second would look like a replay. Each signed test
// starts from a clean cache.
func resetSeenSignatures(t coretypes.TB) {
	t.Helper()
	seenSignaturesMu.Lock()
	defer seenSignaturesMu.Unlock()
	seenSignatures = map[string]time.Time{}
}

func sealTestOwner(t coretypes.TB, s *CoreServer) (seed []byte, aid string) {
	t.Helper()
	resetSeenSignatures(t)
	seed = make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	aid = "EOWNERTESTAID"
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       aid,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}); err != nil {
		t.Fatalf("seal owner authority: %v", err)
	}
	return seed, aid
}

func signed(t coretypes.TB, method, path, body string, seed []byte, at time.Time) *http.Request {
	t.Helper()
	return signedFor(t, "", method, path, body, seed, at)
}

// signedFor is signed, naming the Identity Agent target, as every owner request
// to an Identity Agent with an identifier must.
func signedFor(t coretypes.TB, target, method, path, body string, seed []byte, at time.Time) *http.Request {
	t.Helper()
	req := remote(method, path, body)
	stamp := at.UTC().Format(time.RFC3339)
	sig, err := SignOwnerRequest(target, method, path, stamp, []byte(body), seed)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if target != "" {
		req.Header.Set(headerOwnerFor, target)
	}
	req.Header.Set(headerOwnerSig, sig)
	req.Header.Set(headerOwnerTimestamp, stamp)
	return req
}

// testOwnerSecret is the local owner secret test servers are given, and the
// one a test request carries when it stands for the owner at this computer.
const testOwnerSecret = "test-local-owner-secret-0123456789abcdef"

func signingPair(t coretypes.TB, b byte) ([]byte, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return seed, iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

func chainSays(t coretypes.TB, s *CoreServer) map[string]any {
	t.Helper()
	req := local("GET", "/api/activity/chain", "")
	rec := httptest.NewRecorder()
	s.handleVerifyAuditChain(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("checking the log: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func recordDB(t coretypes.TB, s *CoreServer) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(s.DataDir, "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// vaultForTest is s's credential vault, made over dir when s has none yet, so
// a sandbox manager a test makes adds credentials from the vault the server
// keeps them in, as it does when the server makes both.
func (s *CoreServer) vaultForTest(dir string) *vault.CredentialVault {
	if s.Vault == nil {
		s.Vault = vault.NewCredentialVault(dir)
	}
	return s.Vault
}

// logForTest is s's activity log, opened in dir when s has none yet and closed
// when the test ends, so a sandbox manager a test makes writes to the log the
// server reads, as it does when the server makes both.
func (s *CoreServer) logForTest(t coretypes.TB, dir string) *activitylog.Log {
	t.Helper()
	if s.ActivityLog == nil {
		l, err := activitylog.Open(dir)
		if err != nil {
			t.Fatalf("open the activity log: %v", err)
		}
		t.Cleanup(func() { l.Close() })
		s.ActivityLog = l
	}
	return s.ActivityLog
}

// anAuthorisedMachine puts a controller on an agent and returns the machine's
// identifier and the seed it signs with.
//
// Both are derived from the test's own name, so every test is a DIFFERENT
// machine. That is how it works in life, and here it also keeps two tests from
// producing byte-identical signed requests within the same second — which the
// replay guard would correctly refuse as a reused signature, failing the second
// test for a reason that has nothing to do with what it was checking.
func anAuthorisedMachine(t coretypes.TB, s *CoreServer, grade ControllerGrade) (string, []byte) {
	t.Helper()
	// The device holding this identity's root key, because it is the only thing
	// entitled to say how well somebody was authenticated.
	ownerSeedForTest(t, s)
	seed := make([]byte, ed25519.SeedSize)
	for i, c := range []byte(t.Name()) {
		seed[i%ed25519.SeedSize] ^= c + byte(i)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	// A controller is named by its own key, so the identifier is derived rather
	// than invented — the agent refuses a grant whose two halves disagree.
	aid := iacrypto.NonTransferableAIDQB64(pub)
	if _, err := s.controllers().Grant(ControllerGrant{
		ControllerAID: aid,
		PublicKey:     iacrypto.VerkeyQB64(pub),
		Label:         "the laptop in the study",
		Grade:         grade,
	}, time.Now().UTC()); err != nil {
		t.Fatalf("authorising the machine: %v", err)
	}
	return aid, seed
}

// asThatMachine builds a request signed by a controller, asserting an
// authentication level measured at a given moment.
//
// Passing an empty level means the machine reported nothing, which is different
// from reporting a weak one.
func asThatMachine(t coretypes.TB, aid, method, path, body string, seed []byte,
	level authprovider.Level, measuredAt time.Time) *http.Request {
	t.Helper()
	return asThatMachineTo(t, "", aid, method, path, body, seed, level, measuredAt)
}

// asThatMachineTo is asThatMachine for a request naming the Identity Agent
// target, as every request to a named Identity Agent must.
func asThatMachineTo(t coretypes.TB, target, aid, method, path, body string, seed []byte,
	level authprovider.Level, measuredAt time.Time) *http.Request {
	t.Helper()
	return asThatMachineScored(t, target, aid, method, path, body, seed, level, measuredAt, 80)
}

// asThatMachineScored is asThatMachineTo with the score the root device
// vouches for chosen.
func asThatMachineScored(t coretypes.TB, target, aid, method, path, body string, seed []byte,
	level authprovider.Level, measuredAt time.Time, score int) *http.Request {
	t.Helper()
	req := remote(method, path, body)
	stamp := time.Now().UTC().Format(time.RFC3339)

	asserted := authprovider.Unmeasured("")
	if level != "" {
		asserted = authprovider.Result{
			Level: level, Measured: true, At: measuredAt.UTC(), Score: score,
		}
		req.Header.Set(headerControllerAuthLevel, string(level))
		req.Header.Set(headerControllerAuthAt, measuredAt.UTC().Format(time.RFC3339))
		req.Header.Set(headerControllerAuthScore, fmt.Sprint(score))
		// Vouched for by the root-identity device. Without this the level is the
		// machine scoring itself, which the agent refuses.
		if vouch := theRootDeviceVouches(t, aid, level, measuredAt, score); vouch != "" {
			req.Header.Set(headerAuthLevelVouchedBy, vouch)
		}
	}

	sig, err := login.SignString(
		canonicalControllerRequest(aid, target, method, path, stamp, asserted, []byte(body)), seed)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if target != "" {
		req.Header.Set(headerControllerFor, target)
	}
	req.Header.Set(headerControllerAID, aid)
	req.Header.Set(headerControllerSig, sig)
	req.Header.Set(headerControllerTimestamp, stamp)
	return req
}

// acdcOf is a stored credential's body.
func acdcOf(t coretypes.TB, s *CoreServer, said string) map[string]interface{} {
	t.Helper()
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		t.Fatalf("credential %s is not on record: %v", said, err)
	}
	raw, err := base64.StdEncoding.DecodeString(rec.AcdcJson)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func credentialsOf(t coretypes.TB, s *CoreServer, holder string) []store.CredentialRecord {
	t.Helper()
	all, _ := s.DataStore.GetCredentials()
	var out []store.CredentialRecord
	for _, c := range all {
		if c.HolderAID == holder {
			out = append(out, c)
		}
	}
	return out
}

func testOwnerSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

// awaiting is what the approval list says is waiting.
func awaiting(t coretypes.TB, s *CoreServer) (machines, agents map[string]string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleGrantsAwaitingApproval(rec, local("GET", "/api/grants/awaiting-approval", ""))
	var out struct {
		Machines []map[string]interface{} `json:"machines"`
		Agents   []map[string]interface{} `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("awaiting approval: %d %s", rec.Code, rec.Body.String())
	}
	machines, agents = map[string]string{}, map[string]string{}
	for _, m := range out.Machines {
		machines[m["controller_aid"].(string)], _ = m["awaiting"].(string)
	}
	for _, a := range out.Agents {
		agents[a["asset_id"].(string)], _ = a["awaiting"].(string)
	}
	return machines, agents
}

// everythingRuns is every path that once gave a grant without being asked:
// starting, and the anchoring tick.
func everythingRuns(s *CoreServer) {
	s.prepareKeyLogs()
	s.anchorRecord()
}

// withController is r as a machine's request reaches a handler.
func withController(r *http.Request, g ControllerGrant) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), controllerContextKey{}, g))
}

// endsItsBackgroundWork stops the background work a test's server started and
// waits for it, when the test ends, the way Stop does for a running server.
// These servers are never started, so nothing else would: work still writing
// into the data directory when the test ends is what made removing that
// directory fail at random.
func endsItsBackgroundWork(t coretypes.TB, s *CoreServer) {
	t.Helper()
	t.Cleanup(func() {
		if !s.endBackground(backgroundStopWait) {
			t.Error("background work was still running when the test ended")
		}
	})
}

// everyEntry is a route table as the gate reads it: the core's own entries
// and those of every add-on registered.
func everyEntry(core map[string]string, addons func(Addon) map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range core {
		out[k] = v
	}
	for _, a := range registeredAddons() {
		for k, v := range addons(a) {
			out[k] = v
		}
	}
	return out
}

// foundedWith founds the organisation in s, naming witnesses when given, and
// delegates an AI agent from it.
func foundedWith(t coretypes.TB, s *CoreServer, witnesses []string, toad int) (*CoreServer, *asset.Asset) {
	t.Helper()
	rootAID, e := foundOrganisation(t, s, witnesses, toad)
	aSigner, _ := keri.GenerateSigner(true)
	aNext, _ := keri.GenerateSigner(true)
	aPub, _ := aSigner.PublicKey()
	aNextPub, _ := aNext.PublicKey()
	dip, err := e.CreateDelegatedInception(aPub, aNextPub, "Research assistant", rootAID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.saveDelegationAnchor(rootAID, dip); err != nil {
		t.Fatal(err)
	}
	return s, &asset.Asset{
		ID: "agent-1", DisplayName: "Research assistant", AssetType: "ai_agent",
		PairwiseAID: dip.AID, DelegatorAID: rootAID,
		Capabilities: []string{"infra.zone.list", "system.info.read"},
	}
}

func fulfilWith(t coretypes.TB, s *CoreServer, id, sig string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleFulfilSigningRequest(rec, withID(ownerRequest("POST", "/api/signing-requests/"+id+"/fulfil",
		strings.NewReader(`{"signature":"`+sig+`"}`), s), id))
	return rec
}

// orgWorld is an organisation that holds its own key, founded as
// foundOrganisation founds it.
func orgWorld(t coretypes.TB) *CoreServer {
	t.Helper()
	s := agentWithDerivedIdentity(t) // the organisation's key is derivable here
	foundOrganisation(t, s, nil, 0)
	return s
}

// ownerSeedForTest gives the agent a root-identity device whose statements about
// authentication it will accept, and returns that device's seed.
//
// Stored in a package-level map keyed by the test, because a controller request
// is built by a helper that does not otherwise know the owner.
func ownerSeedForTest(t coretypes.TB, s *CoreServer) []byte {
	t.Helper()
	seed, _ := sealTestOwner(t, s)
	rootDeviceSeeds[t.Name()] = seed
	t.Cleanup(func() { delete(rootDeviceSeeds, t.Name()) })
	return seed
}

func signWith(req store.SigningRequest, seed []byte) string {
	payload, _ := base64.StdEncoding.DecodeString(req.PayloadB64)
	sig, _ := login.SignString(string(payload), seed)
	return sig
}

// theRootDeviceVouches is the phone signing "this person reached this level, at
// this moment, for this machine".
func theRootDeviceVouches(t coretypes.TB, controllerAID string, level authprovider.Level,
	at time.Time, score int) string {
	t.Helper()
	seed, ok := rootDeviceSeeds[t.Name()]
	if !ok {
		return ""
	}
	sig, err := login.SignString(
		canonicalAuthLevelStatement(controllerAID, level, at, score), seed)
	if err != nil {
		t.Fatalf("the root device could not vouch: %v", err)
	}
	return sig
}

// foundOrganisation founds an organisation that holds its own key in s, naming
// witnesses when given: founded and reloaded into the engine the way startup
// reloads it, with its founding event signed and stored. It returns the
// organisation's identifier and the engine that holds its key.
func foundOrganisation(t coretypes.TB, s *CoreServer, witnesses []string, toad int) (string, *keriengine.Engine) {
	t.Helper()
	e := keriengine.New()
	s.KeriDriver = e
	s.engineSigns()

	owner, _ := s.DataStore.GetIdentity()
	seed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	next, _ := keri.GenerateSigner(true)
	nextPub, _ := next.PublicKey()
	founding := keriengine.New()
	root, err := founding.Incept(drivers.InceptionRequest{
		PublicKey: owner.PublicKey, NextPublicKey: nextPub, Name: "owner", Witnesses: witnesses, Toad: toad,
	})
	if err != nil {
		t.Fatal(err)
	}
	kel, _ := founding.GetKel("owner")
	raw, _ := base64.StdEncoding.DecodeString(root.RawBytesB64)
	sig, err := login.SignString(string(raw), seed)
	if err != nil {
		t.Fatal(err)
	}
	icp, _ := json.Marshal(kel.KEL[0])
	owner.AID, owner.NextKeyDigest = root.AID, root.NextKeyDigest
	if err := s.DataStore.SaveIdentity(*owner); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID: root.AID, SequenceNumber: 0, EventType: "icp", EventJSON: string(icp),
		PublicKey: owner.PublicKey, RawBytesB64: root.RawBytesB64, CesrSignature: sig,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReloadIdentity(&drivers.DriverReloadIdentityRequest{
		AID: root.AID, PublicKey: root.PublicKey, NextKeyDigest: root.NextKeyDigest,
		KEL: kel.KEL, RawEventsB64: kel.RawEventsB64,
	}); err != nil {
		t.Fatal(err)
	}
	return root.AID, e
}

// ownerRequest builds a request this agent will treat as its owner's.
//
// Ownership is loopback-without-forwarding-headers, so the test has to say
// where it is coming from. httptest defaults to a non-loopback address, which
// would make every owner-only test pass for the wrong reason.
func ownerRequest(method, path string, body io.Reader, _ *CoreServer) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	return r
}

var rootDeviceSeeds = map[string][]byte{}

func withID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
