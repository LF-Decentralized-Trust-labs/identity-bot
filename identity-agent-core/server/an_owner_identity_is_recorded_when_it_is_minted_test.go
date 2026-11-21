package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// The kind is kept with the index at mint: what the request says, nothing
// where it says nothing, and what the claim says for an identity minted
// while adopting.
func TestTheKindIsKeptWithTheIndexAtMint(t *testing.T) {
	s := adoptingOwner(t)
	mint := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleMintMachineOwner(rec, httptest.NewRequest(http.MethodPost, "/api/machines/owner-identity", strings.NewReader(body)))
		return rec
	}
	for body, want := range map[string]string{
		`{"kind":"organisation"}`: machineKindOrganisation,
		`{"kind":"individual"}`:   machineKindIndividual,
		`{}`:                      "",
		``:                        "",
	} {
		rec := mint(body)
		if rec.Code != http.StatusOK {
			t.Fatalf("minting with %q: %d %s", body, rec.Code, rec.Body.String())
		}
		var minted machineOwnerResponse
		json.NewDecoder(rec.Body).Decode(&minted)
		id, found, err := s.DataStore.MachineOwnerIdentity(minted.AID)
		if err != nil || !found || id.KeyIndex <= 0 || id.Kind != want {
			t.Fatalf("minted with %q, kept %+v (found=%v, %v)", body, id, found, err)
		}
	}
	if rec := mint(`{"kind":"a fleet"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown kind was minted for: %d %s", rec.Code, rec.Body.String())
	}
	if all, _ := s.DataStore.MachineOwnerIdentities(); len(all) != 4 {
		t.Fatalf("%d owner identities are kept, want the four minted", len(all))
	}
}

// An owner identity minted while adopting a machine is recorded as every
// owner identity is, so it can be signed as afterwards.
func TestAnOwnerIdentityMintedWhileAdoptingCanBeSignedAsAfterwards(t *testing.T) {
	s := adoptingOwner(t)
	var sent pairingCompleteRequest
	box := adoptingMachine(t, &sent)
	defer box.Close()
	if rec := adoptFrom(t, s, box.URL); rec.Code != http.StatusOK {
		t.Fatalf("adoption failed: %d %s", rec.Code, rec.Body.String())
	}
	if sent.OwnerAID == "" {
		t.Fatal("the machine was told of no owner")
	}

	rec := askToSignAs(t, s, `{"owner_aid":"`+sent.OwnerAID+`","method":"GET","path":"/api/identity","for":"EThatMachine"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("this device would not sign as the identity it adopted the machine with: %d %s",
			rec.Code, rec.Body.String())
	}
	id, found, err := s.DataStore.MachineOwnerIdentity(sent.OwnerAID)
	if err != nil || !found || id.KeyIndex <= 0 || id.Kind != machineKindIndividual {
		t.Fatalf("the identity minted while adopting is kept as %+v (found=%v, %v)", id, found, err)
	}
	// Its founding is kept, signed, so its log can be proved and extended.
	events, err := s.DataStore.GetEvents(sent.OwnerAID)
	if err != nil || len(events) != 1 || events[0].RawBytesB64 == "" || len(events[0].ControllerSignatures()) == 0 {
		t.Fatalf("its key log is kept as %d events (%v)", len(events), err)
	}
}

// adoptionClaimedAs asks s to adopt a stand-in machine as owner, an owner
// identity it minted, and returns the answer and what the machine was sent
// to complete the claim.
func adoptionClaimedAs(t *testing.T, s *CoreServer, owner string) (*httptest.ResponseRecorder, pairingCompleteRequest) {
	t.Helper()
	var sent pairingCompleteRequest
	box := adoptingMachine(t, &sent)
	defer box.Close()
	body := `{"box_url":"` + box.URL + `","adoption_code":"code","owner_aid":"` + owner + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/adopt", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	rec := httptest.NewRecorder()
	s.handlePairingAdopt(rec, req)
	return rec, sent
}

func refusedToClaim(t *testing.T, rec *httptest.ResponseRecorder, sent pairingCompleteRequest, because string) {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected a refusal, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), because) {
		t.Fatalf("the refusal does not say %q: %s", because, rec.Body.String())
	}
	if sent.OwnerAID != "" {
		t.Fatal("the machine was sent a claim by the refused owner identity")
	}
}

// One owner identity owns one Identity Agent (ADR-087 decision 8): one that
// already anchors an Identity Agent claims no other machine.
func TestAdoptionRefusesAnOwnerIdentityThatAlreadyAnchorsAnIdentityAgent(t *testing.T) {
	s := adoptingOwner(t)
	owner, _, err := s.mintAnIdentityToClaimAMachineWith(machineKindIndividual)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DataStore.(*store.SQLiteStore).DB().Exec(
		`UPDATE machine_owner_identities SET anchored_m = ? WHERE aid = ?`,
		"EMachineOneMachineOneMachineOneMachineOne000", owner); err != nil {
		t.Fatal(err)
	}
	rec, sent := adoptionClaimedAs(t, s, owner)
	refusedToClaim(t, rec, sent, "already anchors")
}

// An owner identity whose log holds two events at one place owns nothing,
// so it claims no machine.
func TestAdoptionRefusesAnOwnerIdentityWhoseLogIsDuplicitous(t *testing.T) {
	s := adoptingOwner(t)
	owner, _, err := s.mintAnIdentityToClaimAMachineWith(machineKindIndividual)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.MarkMachineOwnerIdentityDuplicitous(owner, 1); err != nil {
		t.Fatal(err)
	}
	rec, sent := adoptionClaimedAs(t, s, owner)
	refusedToClaim(t, rec, sent, "two events are known")
}

// A given-up owner identity may sign only the claim a machine was told to
// expect from it, beside a fresh owner identity as the founding owner
// (ADR-087 decision 7). Adoption sends no founding owner, so it refuses.
func TestAdoptionRefusesAGivenUpOwnerIdentity(t *testing.T) {
	s := adoptingOwner(t)
	owner, _, err := s.mintAnIdentityToClaimAMachineWith(machineKindIndividual)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.GiveUpMachineOwnerIdentity(owner, "EMachineOneMachineOneMachineOneMachineOne000"); err != nil {
		t.Fatal(err)
	}
	rec, sent := adoptionClaimedAs(t, s, owner)
	refusedToClaim(t, rec, sent, "was given up")
}

// An owner identity minted and not yet used claims a machine.
func TestAdoptionAcceptsAnOwnerIdentityThatAnchorsNothingYet(t *testing.T) {
	s := adoptingOwner(t)
	owner, _, err := s.mintAnIdentityToClaimAMachineWith(machineKindIndividual)
	if err != nil {
		t.Fatal(err)
	}
	rec, sent := adoptionClaimedAs(t, s, owner)
	if rec.Code != http.StatusOK || sent.OwnerAID != owner {
		t.Fatalf("a fresh owner identity was refused: %d %s", rec.Code, rec.Body.String())
	}
}
