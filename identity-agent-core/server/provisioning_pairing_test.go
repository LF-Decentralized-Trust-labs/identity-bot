package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// The one unauthenticated endpoint has to earn it. These tests are the terms.

// It must answer before an owner exists — that is the entire point. A fresh
// instance has no identity and no owner, so an owner-gated endpoint would be
// unreachable by anyone, forever.
func TestPairingIsReachableBeforeAnOwnerExists(t *testing.T) {
	if got := classify("GET", "/api/provisioning/pairing"); got != accessPublic {
		t.Fatalf("classified %q — a fresh instance would be unreachable", got)
	}
}

// Once the instance has an identity it has been paired, and an unauthenticated
// caller has no business here any more.
func TestPairingStopsAnsweringOncePaired(t *testing.T) {
	resetPairingOfferForTest()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	if err := ds.SaveIdentity(store.IdentityState{AID: "EPAIREDALREADY", PublicKey: "DKEY"}); err != nil {
		t.Skipf("cannot save identity: %v", err)
	}
	s := &CoreServer{DataDir: dir, DataStore: ds}

	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))
	if w.Code != http.StatusConflict {
		t.Errorf("an already-paired instance still offered pairing: %d %s", w.Code, w.Body)
	}
}

// It discloses a pairwise AID and an OOBI, and nothing else. No root AID, no
// key, no profile, nothing about a person.
func TestPairingDisclosesNothingBeyondThePairwiseOffer(t *testing.T) {
	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = &pairingOffer{AID: "EPAIRWISE", OOBI: "https://box.example/public/oobi/EPAIRWISE"}
	pairingOnce.Unlock()

	s := &CoreServer{DataDir: t.TempDir()}
	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	// The offer carries what somebody pairing needs and nothing more: where the
	// instance is, and proof they are the one it was set up for. Anything beyond
	// this list is a disclosure by an endpoint that answers without authorisation.
	allowed := map[string]bool{"aid": true, "oobi": true, "adoption_code": true, "attestation": true, "attestation_binding": true}
	for field := range body {
		if !allowed[field] {
			t.Errorf("the offer discloses %q, which nothing pairing needs", field)
		}
	}
	if body["aid"] == nil || body["oobi"] == nil {
		t.Fatalf("the offer must carry an aid and an oobi, got %v", body)
	}
}

// An offer without a code cannot be adopted — adoption compares what it is
// given against the offer, and an empty expectation refuses everything. So the
// two have to be built together, and this is the test that says so.
func TestEveryMintedOfferCarriesAnAdoptionCode(t *testing.T) {
	offer, err := newPairingOffer("EPAIRWISE", "https://box.example/public/oobi/EPAIRWISE")
	if err != nil {
		t.Fatalf("mint offer: %v", err)
	}
	if offer.AdoptionCode == "" {
		t.Fatal("the offer carries no adoption code, so this instance could never be adopted")
	}

	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = offer
	pairingOnce.Unlock()

	if expectedAdoptionCode() != offer.AdoptionCode {
		t.Fatal("the code an adoption is checked against is not the code that was offered")
	}
}

// A setup retry must describe the same instance. Minting a second AID would
// hand the user an OOBI for something other than what was reported ready.
func TestPairingMintsOnce(t *testing.T) {
	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = &pairingOffer{AID: "EFIRST", OOBI: "https://box.example/public/oobi/EFIRST"}
	pairingOnce.Unlock()

	s := &CoreServer{DataDir: t.TempDir()}
	var seen []string
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))
		var body pairingOffer
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		seen = append(seen, body.AID)
	}
	for _, aid := range seen {
		if aid != seen[0] {
			t.Fatalf("the offer changed between calls: %v", seen)
		}
	}
}

// Absence of an attestation is a real answer, not a gap. Outside a sealed VM
// the field is empty, and a caller that requires sealed infrastructure must be
// able to tell that from a report it simply did not parse.
func TestPairingOfferOmitsAttestationOutsideASealedVM(t *testing.T) {
	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = &pairingOffer{AID: "EPAIRWISE", OOBI: "https://box.example/public/oobi/EPAIRWISE"}
	pairingOnce.Unlock()

	s := &CoreServer{DataDir: t.TempDir()}
	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, present := body["attestation"]; present {
		t.Error("an attestation appeared on a machine that cannot produce one")
	}
}

// When a report is present it must be bound to the AID in the same response,
// or it proves something about a different instance.
func TestAttestationIsBoundToTheAdvertisedAID(t *testing.T) {
	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = &pairingOffer{
		AID:                "EPAIRWISE",
		OOBI:               "https://box.example/public/oobi/EPAIRWISE",
		Attestation:        "AAAA",
		AttestationBinding: `blake3-256(IA-SNP-BIND-V1\nEPAIRWISE)`,
	}
	pairingOnce.Unlock()

	s := &CoreServer{DataDir: t.TempDir()}
	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))

	var offer pairingOffer
	if err := json.Unmarshal(w.Body.Bytes(), &offer); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if !strings.Contains(offer.AttestationBinding, offer.AID) {
		t.Errorf("the report is bound to %q but the offer advertises %q — it proves nothing about this instance",
			offer.AttestationBinding, offer.AID)
	}
}
