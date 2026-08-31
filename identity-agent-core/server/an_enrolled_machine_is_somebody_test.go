package server

import (
	"crypto/ed25519"
	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A machine this identity enrolled is recognised as itself, and is granted
// nothing by being recognised.
//
// Those are two claims and the second is the load-bearing one. The enrolment
// ceremony already anchors a delegated inception over a key the machine
// generated and records that key, so the agent has everything it needs to know
// the machine again — and until now nothing asked, so an enrolled machine
// arrived as an anonymous remote caller and its own audit trail said so.
//
// Identifying is not authorising. authorize() lets anybody holding any scope
// reach a scoped route, so a resolver that filled in scopes here would hand
// every enrolled machine the capability surface as a side effect of being
// recognised. What such a machine may DO is a decision, and a separate one.

// signedAs builds a request signed by a machine's own key, as one arriving from
// elsewhere.
func signedAs(t *testing.T, key ed25519.PrivateKey, aid, method, path string) *http.Request {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339)
	sig, err := SignOwnerRequest(method, path, stamp, nil, key.Seed())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "203.0.113.9:51000"
	r.Header.Set(headerAssetAID, aid)
	r.Header.Set(headerAssetTimestamp, stamp)
	r.Header.Set(headerAssetSig, sig)
	return r
}

func TestAnEnrolledMachineIsRecognisedAsItself(t *testing.T) {
	s := notifyTestServer(t)
	const aid = "EMACHINE-ONE"
	key := enrolledMachine(t, s, aid)

	cc := s.resolveCaller(signedAs(t, key, aid, http.MethodGet, "/api/identity"))

	if cc.CallerAID != aid {
		t.Fatalf("the machine was not recognised: CallerAID = %q", cc.CallerAID)
	}
	// Recorded as what it is: a signature carried in headers.
	if cc.AuthLevel != "signed_headers" {
		t.Errorf("the signature was not recorded: AuthLevel = %q", cc.AuthLevel)
	}
	// And NOT as an envelope, which is documented to mean a fresh, non-replayed
	// signed-request envelope. Claiming it would let enrichCallerFromIdentity
	// hand an AI agent's machine a capability ceiling for signing a header.
	if cc.EnvelopeVerified {
		t.Error("a header signature was recorded as a verified envelope, which is " +
			"the stronger proof this path does not have")
	}

	// The lineage, owner last. This is what lets an audit entry say "owner ->
	// machine" rather than naming a key nobody can place.
	want := []string{aid, "EORG-ROOT"}
	if len(cc.DelegationChain) != len(want) {
		t.Fatalf("delegation chain = %v, want %v", cc.DelegationChain, want)
	}
	for i := range want {
		if cc.DelegationChain[i] != want[i] {
			t.Fatalf("delegation chain = %v, want %v", cc.DelegationChain, want)
		}
	}
}

// Recognition must not become permission. If this ever fails, an enrolled
// machine has been given the scoped surface by the act of being identified.
func TestBeingRecognisedGrantsNothing(t *testing.T) {
	s := notifyTestServer(t)
	const aid = "EMACHINE-ONE"
	key := enrolledMachine(t, s, aid)

	cc := s.resolveCaller(signedAs(t, key, aid, http.MethodGet, "/api/identity"))
	if len(cc.Scopes) != 0 {
		t.Fatalf("being recognised granted scopes %v — authorize() admits any caller "+
			"holding any scope to a scoped route, so this hands over the capability "+
			"surface as a side effect of knowing who is asking", cc.Scopes)
	}
	if !cc.Remote {
		t.Error("a machine signing from elsewhere was treated as local")
	}
}

// A signature that does not verify leaves the caller anonymous rather than
// half-identified. The claimed AID is attacker-supplied until the signature
// says otherwise.
func TestAnUnprovenClaimIsNobody(t *testing.T) {
	s := notifyTestServer(t)
	const aid = "EMACHINE-ONE"
	enrolledMachine(t, s, aid)

	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	cc := s.resolveCaller(signedAs(t, other, aid, http.MethodGet, "/api/identity"))

	if cc.CallerAID == aid {
		t.Fatal("a request signed by a different key was accepted as that machine")
	}
	if len(cc.DelegationChain) != 0 {
		t.Fatalf("an unproven caller was given a lineage: %v", cc.DelegationChain)
	}
}

// enrolledMachineOf records an asset delegated from a named root, so a test can
// vary whose it is. enrolledMachine in asset_notify_test.go is this with the
// root fixed.
func enrolledMachineOf(t *testing.T, s *CoreServer, aid, rootAID string) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "a second machine's key, fixed for the test")
	key := ed25519.NewKeyFromSeed(seed)

	if err := s.assetHandler.Store.UpsertAsset(asset.Asset{
		ID:              "asset-2",
		DisplayName:     "something this identity owns and delegated to",
		AssetType:       "host",
		PairwiseAID:     aid,
		PublicKey:       iacrypto.VerkeyQB64(key.Public().(ed25519.PublicKey)),
		DelegationModel: "delegated",
		DelegatorAID:    rootAID,
	}); err != nil {
		t.Fatal(err)
	}
	return key
}

// Recognition must still grant nothing after the whole resolution chain has
// run, not only after the resolver.
//
// ResolveEndpointCaller resolves, verifies any envelope, and then calls
// enrichCallerFromIdentity — which looks up a provisioned agent's capability
// ceiling and would fill Scopes. It bails here only because DelegationChain is
// already set, so the "grants nothing" property currently rests on a guard
// clause in another file rather than on anything that says so.
//
// This asserts the property where it has to hold. Without it, dropping or
// reordering that guard hands an enrolled machine a capability ceiling and
// nothing fails.
func TestRecognitionGrantsNothingThroughTheWholeChain(t *testing.T) {
	s := notifyTestServer(t)
	const aid = "EMACHINE-ONE"
	key := enrolledMachine(t, s, aid)

	cc, err := s.ResolveEndpointCaller(
		signedAs(t, key, aid, http.MethodGet, "/api/identity"), http.MethodGet, nil)
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if cc.CallerAID != aid {
		t.Fatalf("the machine was not recognised through the chain: %q", cc.CallerAID)
	}
	if len(cc.Scopes) != 0 {
		t.Fatalf("the full chain granted scopes %v to a machine that only proved who it is", cc.Scopes)
	}
	if cc.GrantSAID != "" {
		t.Fatalf("a capability grant was attached: %q", cc.GrantSAID)
	}
}

// An AI agent's machine gets no capability ceiling for signing a header.
//
// This is the case the host fixture above cannot show. enrichCallerFromIdentity
// grants an envelope-proven caller the scopes of its provisioned agent, and
// findAgentAssetByAID only matches assets of type ai_agent — so a host asset
// never reaches it whatever the resolver claims, and the property looked safe
// for the wrong reason.
//
// Claiming EnvelopeVerified here would have handed those scopes over for a
// signature carried in headers. It bailed anyway, on an unrelated guard in
// another file; this asserts it bails for the reason that is actually true.
func TestAnAIAgentsMachineGetsNoCeilingForSigningAHeader(t *testing.T) {
	s := notifyTestServer(t)
	const aid = "EAI-AGENT-MACHINE"

	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "an ai agent's machine key, for the test")
	key := ed25519.NewKeyFromSeed(seed)
	if err := s.assetHandler.Store.UpsertAsset(asset.Asset{
		ID:              "asset-ai-1",
		DisplayName:     "an AI agent acting in this identity's name",
		AssetType:       "ai_agent",
		PairwiseAID:     aid,
		PublicKey:       iacrypto.VerkeyQB64(key.Public().(ed25519.PublicKey)),
		DelegationModel: "delegated",
		DelegatorAID:    "EORG-ROOT",
		Capabilities:    []string{"send.email", "read.calendar"},
	}); err != nil {
		t.Fatal(err)
	}

	cc, err := s.ResolveEndpointCaller(
		signedAs(t, key, aid, http.MethodGet, "/api/identity"), http.MethodGet, nil)
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if cc.CallerAID != aid {
		t.Fatalf("the machine was not recognised: %q", cc.CallerAID)
	}
	if len(cc.Scopes) != 0 {
		t.Fatalf("signing a header bought the capability ceiling %v", cc.Scopes)
	}
}
