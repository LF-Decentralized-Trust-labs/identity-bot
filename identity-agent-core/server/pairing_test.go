package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// realKey is a well-formed Ed25519 public key: the owner key is checked with
// the same decoder the owner-signature path uses, so a fixture has to be one.
func realKey() string {
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(pub)
}

// The rule the whole ceremony exists to enforce: the delegation must be over
// the key this instance generated. Without it a controller could delegate to a
// key it holds, and the box would end up "adopted" with an identity it cannot
// sign for — or one somebody else can.
func TestDelegationMustBeOverThisInstancesKey(t *testing.T) {
	const ours = "DOURKEY"
	req := pairingCompleteRequest{
		DipEvent: map[string]interface{}{
			"t": "dip", "i": "EDELEGATED", "di": "EROOT",
			"k": []interface{}{"DSOMEONEELSESKEY"},
		},
		DelegatorAID: "EROOT", OwnerAID: "EOWNER", OwnerPublicKey: realKey(),
	}
	if err := validateDelegation(req, ours); err == nil {
		t.Fatal("a delegation over another key was accepted")
	}

	req.DipEvent["k"] = []interface{}{ours}
	if err := validateDelegation(req, ours); err != nil {
		t.Fatalf("a correct delegation was refused: %v", err)
	}
}

func TestDelegationMustNameADelegator(t *testing.T) {
	const ours = "DOURKEY"
	for name, dip := range map[string]map[string]interface{}{
		"no delegator":     {"t": "dip", "i": "EDELEGATED", "k": []interface{}{ours}},
		"self-delegating":  {"t": "dip", "i": "EROOT", "di": "EROOT", "k": []interface{}{ours}},
		"not a dip":        {"t": "icp", "i": "EDELEGATED", "di": "EROOT", "k": []interface{}{ours}},
		"no delegated aid": {"t": "dip", "di": "EROOT", "k": []interface{}{ours}},
	} {
		req := pairingCompleteRequest{DipEvent: dip, OwnerAID: "EOWNER", OwnerPublicKey: realKey()}
		if err := validateDelegation(req, ours); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A delegation that claims one delegator while the event names another is
// either a bug or an attempt to misattribute the adoption.
func TestClaimedDelegatorMustMatchTheEvent(t *testing.T) {
	const ours = "DOURKEY"
	req := pairingCompleteRequest{
		DipEvent: map[string]interface{}{
			"t": "dip", "i": "EDELEGATED", "di": "EACTUAL", "k": []interface{}{ours},
		},
		DelegatorAID: "ECLAIMED", OwnerAID: "EOWNER", OwnerPublicKey: realKey(),
	}
	if err := validateDelegation(req, ours); err == nil {
		t.Fatal("a mismatched delegator claim was accepted")
	}
}

// An adopted instance with no owner would be administrable by nobody, and a
// later call to name one is a window somebody else could step into.
func TestAdoptionRequiresAnOwner(t *testing.T) {
	const ours = "DOURKEY"
	base := map[string]interface{}{"t": "dip", "i": "EDELEGATED", "di": "EROOT", "k": []interface{}{ours}}
	for name, req := range map[string]pairingCompleteRequest{
		"no owner aid": {DipEvent: base, OwnerPublicKey: realKey()},
		"no owner key": {DipEvent: base, OwnerAID: "EOWNER"},
	} {
		if err := validateDelegation(req, ours); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Both endpoints have to answer before an owner exists — that is the only
// moment they are for — so they cannot be owner-gated.
func TestPairingEndpointsAreReachableBeforeAnOwnerExists(t *testing.T) {
	for _, route := range []struct{ method, pattern string }{
		{"POST", "/api/pairing/begin"},
		{"POST", "/api/pairing/complete"},
	} {
		if got := classify(route.method, route.pattern); got != accessPublic {
			t.Errorf("%s %s classified %q — an unadopted instance could never be adopted",
				route.method, route.pattern, got)
		}
	}
}

// The box URL travels through a browser, a page, a link and possibly a
// screenshot. It cannot be the only thing between a stranger and an unadopted
// instance, so adoption needs a code the address does not carry.
func TestAdoptionCodeIsUnguessableAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		code, err := newAdoptionCode()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if len(code) < 40 {
			t.Errorf("code is only %d characters — that is guessable", len(code))
		}
		if seen[code] {
			t.Fatal("two instances minted the same adoption code")
		}
		seen[code] = true
	}
}

// An instance that never published an offer has no code, and must not be
// adoptable by presenting an empty one.
func TestNoOfferMeansNoCode(t *testing.T) {
	resetPairingOfferForTest()
	if got := expectedAdoptionCode(); got != "" {
		t.Errorf("an instance with no offer reported a code: %q", got)
	}
}
