package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	if len(body) != 2 || body["aid"] == nil || body["oobi"] == nil {
		t.Fatalf("the offer must be exactly {aid, oobi}, got %v", body)
	}
}

// A provisioning retry must describe the same box. Minting a second AID would
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
