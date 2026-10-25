package login

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/secureenclave"
)

func aRelationshipFor(t *testing.T, siteOOBI string) (*Handler, *SiteRelationship) {
	t.Helper()
	store, err := NewRelationshipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Store: store, dataDir: t.TempDir(), HTTPClient: &http.Client{}}
	root := make([]byte, 64)
	copy(root, "a root seed for the registration tests, nothing else 000000000000")
	if err := secureenclave.StoreRootSeed(h.dataDir, root); err != nil {
		t.Fatal(err)
	}
	rel, err := h.getOrCreateRelationship("ESite", &ChallengeBundle{SiteAID: "ESite", SiteOOBI: siteOOBI})
	if err != nil {
		t.Fatal(err)
	}
	return h, rel
}

// A site whose key registry cannot be reached is a sign-in that cannot work,
// and is said to be one now. It used to be swallowed, and surfaced later at the
// site as a sign-in refused for a reason nobody could see.
func TestARegistryThatCannotBeReachedIsAnError(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close() // nothing answers there now

	h, rel := aRelationshipFor(t, url+"/oobi/ESite")
	err := h.registerPairwiseOnDevRelay(rel)
	if err == nil {
		t.Fatal("a registration nobody received was reported as done")
	}
	if !strings.Contains(err.Error(), "could not be reached") {
		t.Errorf("the error does not say what happened: %v", err)
	}
}

// What is registered carries the key log that proves it.
func TestARegistrationCarriesItsProvingKeyLog(t *testing.T) {
	var got map[string]string
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer registry.Close()

	h, rel := aRelationshipFor(t, registry.URL+"/oobi/ESite")
	if err := h.registerPairwiseOnDevRelay(rel); err != nil {
		t.Fatal(err)
	}
	if got["aid"] != rel.PairwiseAID {
		t.Fatalf("registered %q, want %q", got["aid"], rel.PairwiseAID)
	}
	if _, err := KeyFromKeyLog(rel.PairwiseAID, got["key_log"]); err != nil {
		t.Fatalf("the registration's key log does not prove its identifier: %v", err)
	}
}
