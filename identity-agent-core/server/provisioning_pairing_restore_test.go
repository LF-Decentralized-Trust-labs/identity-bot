package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"identity-agent-core/endpoint"
	"identity-agent-core/store"
)

// The address an agent publishes for pairing has to survive the agent
// restarting.
//
// It is handed to whoever is going to claim the agent, so from the moment it is
// published somebody is holding it. An agent that mints a new one on restart
// does not fail, does not log, and looks healthy — it has simply become a
// different agent than the one that person was told to come and claim.

func offerServer(t *testing.T, dir string) *CoreServer {
	t.Helper()
	return &CoreServer{DataDir: dir, EndpointService: endpoint.New(nil, 5050)}
}

func TestThePublishedPairingIdentitySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	kel := []map[string]interface{}{{"t": "icp", "i": "EPUBLISHED"}}
	if err := savePairingOffer(dir, storedPairingOffer{
		AID: "EPUBLISHED", PublicKey: "cHVia2V5", KEL: kel,
	}); err != nil {
		t.Fatalf("record the offer: %v", err)
	}

	// A new process, as after a restart: nothing in memory.
	resetPairingOfferForTest()
	s := offerServer(t, dir)
	s.restorePairingOffer()

	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["aid"] != "EPUBLISHED" {
		t.Fatalf("after a restart the agent offers %v — the address already handed out has stopped resolving",
			body["aid"])
	}

	// Remembering which identity was published is not enough on its own: both
	// registries that make it resolvable live in memory, so without them the
	// agent names an address it cannot serve.
	if _, ok := getPairwiseKey("EPUBLISHED"); !ok {
		t.Error("the verification key was not put back, so did.json will not resolve")
	}
	if _, ok := getPairwiseKEL("EPUBLISHED"); !ok {
		t.Error("the key event log was not put back, so the OOBI will not resolve")
	}
}

// The address is rebuilt from where the agent is reachable now, not stored.
//
// An agent legitimately moves — a tunnel reconnects, a proxy reports a new
// name. Storing the composed OOBI would pin it to wherever it happened to be
// when it first started, which is the same defect one layer along.
func TestTheOfferIsRebuiltAtTheAgentsCurrentAddress(t *testing.T) {
	dir := t.TempDir()
	if err := savePairingOffer(dir, storedPairingOffer{AID: "EMOVED", PublicKey: "cHVia2V5"}); err != nil {
		t.Fatal(err)
	}
	resetPairingOfferForTest()

	t.Setenv("PUBLIC_URL", "https://elsewhere.example/abc")
	s := offerServer(t, dir)
	s.EndpointService.Refresh()
	s.restorePairingOffer()

	pairingOnce.Lock()
	got := pairingOnce.offer
	pairingOnce.Unlock()
	if got == nil {
		t.Fatal("nothing was restored")
	}
	if !strings.HasPrefix(got.OOBI, "https://elsewhere.example/abc/") {
		t.Errorf("the offer points at %q rather than where this agent is now reachable", got.OOBI)
	}
	if !strings.HasSuffix(got.OOBI, "/public/oobi/EMOVED") {
		t.Errorf("the offer does not resolve the published identity: %q", got.OOBI)
	}
}

// An agent that has been claimed has an owner and no longer offers itself, so
// there is nothing to restore and restoring anyway would resurrect an offer it
// has deliberately stopped making.
func TestAClaimedAgentRestoresNothing(t *testing.T) {
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	if err := savePairingOffer(dir, storedPairingOffer{AID: "EOLD", PublicKey: "cHVia2V5"}); err != nil {
		t.Fatal(err)
	}
	if err := ds.SaveIdentity(store.IdentityState{AID: "EOWNED", PublicKey: "DKEY"}); err != nil {
		t.Skipf("cannot save identity: %v", err)
	}
	resetPairingOfferForTest()

	s := offerServer(t, dir)
	s.DataStore = ds
	s.restorePairingOffer()

	pairingOnce.Lock()
	got := pairingOnce.offer
	pairingOnce.Unlock()
	if got != nil {
		t.Errorf("a claimed agent restored a pairing offer for %s", got.AID)
	}
}

// An agent that has never offered itself is the ordinary case, and by far the
// most common one. It must not be an error, and it must not invent an offer.
func TestAnAgentThatNeverPublishedRestoresNothing(t *testing.T) {
	resetPairingOfferForTest()
	s := offerServer(t, t.TempDir())
	s.restorePairingOffer()

	pairingOnce.Lock()
	defer pairingOnce.Unlock()
	if pairingOnce.offer != nil {
		t.Errorf("an agent with nothing recorded invented an offer for %s", pairingOnce.offer.AID)
	}
}

// A corrupt record must not be silently treated as "never published", because
// that is precisely the state that makes the agent mint a new identity and
// strand the address somebody is holding.
func TestAnUnreadableRecordIsAnErrorRatherThanSilence(t *testing.T) {
	dir := t.TempDir()
	if err := savePairingOffer(dir, storedPairingOffer{AID: "EOK", PublicKey: "cHVia2V5"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pairingOfferPath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := loadPairingOffer(dir); err == nil || found {
		t.Errorf("a corrupt record read as found=%v err=%v — the agent would quietly publish a new identity", found, err)
	}
}

// Nothing is left beside the record.
//
// The record is written to a temporary name, flushed, and renamed into place. A
// leftover temporary file is the sign that sequence went wrong somewhere, and it
// is the kind of debris that later reads as a second, older record.
func TestSavingLeavesNoDebrisBesideTheRecord(t *testing.T) {
	dir := t.TempDir()
	if err := savePairingOffer(dir, storedPairingOffer{AID: "EAID", PublicKey: "cHVia2V5"}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("wrote %d files, want exactly the record", len(entries))
	}
}

// A record that cannot be written must say so, because the caller logs it as the
// only warning anybody gets before the next restart loses the identity.
func TestAnUnwritableRecordIsReported(t *testing.T) {
	if err := savePairingOffer("", storedPairingOffer{AID: "EAID"}); err == nil {
		t.Error("saving with nowhere to save to reported success")
	}
	dir := t.TempDir()
	if err := savePairingOffer(dir, storedPairingOffer{}); err == nil {
		t.Error("a record with no AID was accepted, and it names nothing")
	}
}

// The remembered offer is shared, so attaching a per-request proof to it would
// mutate what every later caller is handed.
func TestAttachingAProofDoesNotModifyTheRememberedOffer(t *testing.T) {
	s := offerServer(t, t.TempDir())
	original := &pairingOffer{AID: "EAID", OOBI: "https://example/public/oobi/EAID"}
	got := s.withAttestation(original)
	if got == original {
		t.Fatal("the remembered offer was handed out directly, so a per-request field would persist into it")
	}
	if original.Attestation != "" || original.AttestationBinding != "" {
		t.Error("the remembered offer was modified")
	}
	if got.AID != original.AID || got.OOBI != original.OOBI {
		t.Error("the copy does not carry the identity it is meant to")
	}
}
