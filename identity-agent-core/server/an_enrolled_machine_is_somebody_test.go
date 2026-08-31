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
// recognised. What a controller may DO is a decision, and a separate one.
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
	if cc.AuthLevel != "signed_request" || !cc.EnvelopeVerified {
		t.Errorf("a per-request signature was not recorded as one: AuthLevel=%q verified=%v",
			cc.AuthLevel, cc.EnvelopeVerified)
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

// enrolledMachineOf records a machine delegated from a named root, so a test
// can say whose it is. The organisation fixture in asset_notify_test.go fixes
// the root; an individual's differs only in that value.
func enrolledMachineOf(t *testing.T, s *CoreServer, aid, rootAID string) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "a person's machine key, fixed for the test")
	key := ed25519.NewKeyFromSeed(seed)

	if err := s.assetHandler.Store.UpsertAsset(asset.Asset{
		ID:              "asset-person-1",
		DisplayName:     "a laptop this person controls their agent from",
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
