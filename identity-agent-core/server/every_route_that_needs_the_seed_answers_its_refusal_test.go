package server

import (
	"encoding/json"
	"errors"
	"identity-agent-core/secureenclave"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/buildmode"
	"identity-agent-core/endpoint"
	"identity-agent-core/secureenclave/seedwraptest"
	"identity-agent-core/store"
)

// Every route that has to derive from the root seed answers the root-seed
// refusal the same way when this computer cannot hold one: 412, the one title,
// and the code `root_seed_refused` a client keys on (412 alone is also a
// rotation-required recovery, a front-end arm and a guardianship refusal).
// Taking refuseIfRootSeedRefused out of any one of these handlers turns its
// answer into a 500 or 503 and fails the matching test below.

func theRefusalWasAnswered(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("%s: got %d, want 412: %s", name, w.Code, w.Body)
	}
	var body ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: not the shared body: %v: %s", name, err, w.Body)
	}
	if body.Code != "root_seed_refused" || body.Error != rootSeedRefusalTitle || body.Details == "" {
		t.Fatalf("%s: not the shared refusal body: %s", name, w.Body)
	}
}

func aPhoneThatCannotWrapTheSeed(t *testing.T) *CoreServer {
	t.Helper()
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)
	resetPairingOfferForTest()
	t.Cleanup(resetPairingOfferForTest)
	s := agentWithNoIdentity(t)
	s.EndpointService = endpoint.New(nil, 0)
	return s
}

func TestAskCreateAnswersTheRootSeedRefusal(t *testing.T) {
	s := aPhoneThatCannotWrapTheSeed(t)
	w := httptest.NewRecorder()
	s.handleAskCreate(w, httptest.NewRequest(http.MethodPost, "/api/ask/create", strings.NewReader(`{"t":2}`)))
	theRefusalWasAnswered(t, "ask create", w)
}

func TestAddEmployeeAnswersTheRootSeedRefusal(t *testing.T) {
	s := aPhoneThatCannotWrapTheSeed(t)
	ah, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ah.Store.UpsertAsset(asset.Asset{ID: "site", PairwiseAID: "ESite"}); err != nil {
		t.Fatal(err)
	}
	s.assetHandler = ah
	w := httptest.NewRecorder()
	s.handleCreateEmployeeInvite(w, httptest.NewRequest(http.MethodPost, "/api/employees/invites",
		strings.NewReader(`{"role":"Staff","label":"x","max_uses":1,"asset_id":"site"}`)))
	theRefusalWasAnswered(t, "add employee", w)
}

func TestSignerInviteAnswersTheRootSeedRefusal(t *testing.T) {
	s := aPhoneThatCannotWrapTheSeed(t)
	ah, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.assetHandler = ah
	if err := s.DataStore.SaveProfile(store.ProfileData{OrgName: "An Organisation"}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	w := httptest.NewRecorder()
	s.handleCreateSignerInvite(w, httptest.NewRequest(http.MethodPost, "/api/signer/invites", nil))
	theRefusalWasAnswered(t, "signer invite", w)
}

func TestProvisioningPairingAnswersTheRootSeedRefusal(t *testing.T) {
	s := aPhoneThatCannotWrapTheSeed(t)
	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))
	theRefusalWasAnswered(t, "provisioning pairing", w)
}

// Adopting a machine mints the identity it answers to, which needs the seed.
func TestAdoptAnswersTheRootSeedRefusal(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	s := adoptingOwner(t)
	var sent pairingCompleteRequest
	box := adoptingMachine(t, &sent)
	defer box.Close()

	// The owner's seed is gone from this computer and it can no longer wrap one.
	if err := os.Remove(filepath.Join(s.DataDir, "secureenclave", "root_seed.key")); err != nil {
		t.Fatal(err)
	}
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)

	theRefusalWasAnswered(t, "adopt", adoptFrom(t, s, box.URL))
}

// The refusal survives identitySigningSeed and ownKeyAt: it is still the
// root-seed refusal (so a route can answer 412) as well as errKeyUnavailable.
// Wrapping with %v instead of %w turned it into a bare errKeyUnavailable.
func TestTheRefusalSurvivesTheSigningKeyLookups(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	s := agentWithDerivedIdentity(t)
	if err := os.Remove(filepath.Join(s.DataDir, "secureenclave", "root_seed.key")); err != nil {
		t.Fatal(err)
	}
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)

	_, err := s.identitySigningSeed()
	if !secureenclave.IsRootSeedRefusal(err) || !errors.Is(err, errKeyUnavailable) {
		t.Fatalf("identitySigningSeed lost the refusal: %v", err)
	}
	_, _, err = s.ownKeyAt("DAnyKey")
	if !secureenclave.IsRootSeedRefusal(err) || !errors.Is(err, errKeyUnavailable) {
		t.Fatalf("ownKeyAt lost the refusal: %v", err)
	}
	if err := s.keyCanSign(); !secureenclave.IsRootSeedRefusal(err) {
		t.Fatalf("keyCanSign lost the refusal: %v", err)
	}
}
