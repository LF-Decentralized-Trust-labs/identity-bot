package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
)

// anOwnersAddress serves the owner's key event log at an address, as the
// owner's own agent does, and teaches the engine to verify it to key.
func anOwnersAddress(t *testing.T, s *CoreServer, aid, key string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": aid, "public_key": key, "alias": "owner",
			"kel": []map[string]interface{}{{"t": "icp", "i": aid}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/oobi/" + aid
}

func theEngineVerifies(s *CoreServer, aid, key string) {
	s.KeriDriver.(*driverfake.Engine).ValidateKELFunc = func(got string, _ []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) {
		return &drivers.DriverValidateKELResponse{KelVerified: got == aid, CurrentPublicKey: key}, nil
	}
}

// A ceremony owner who agrees gives their address; the vouch they signed sits
// in the roster beside them. The name is shown, and only because the log was
// recorded at the ceremony.
func TestAnOwnerAddedByCeremonyShowsTheirSignedName(t *testing.T) {
	const org, owner = "EORG", "EOWNER"
	seed := seedOf(7)
	key := keyOf(seed)
	row := vouchRow(t, seed, owner, org, "Sam Ceremony", "Sam Ceremony")
	s := anOrgWithOwners(t, []string{owner}, row)
	theEngineVerifies(s, owner, key)

	// Before the ceremony records anything there is no name.
	if names, _ := listedOwners(t, s); names[owner] != "" {
		t.Fatalf("a name was shown before any log was recorded: %v", names)
	}

	// The same code every way of agreeing runs.
	s.recordWhatNamesAnOwner(owner, anOwnersAddress(t, s, owner, key))

	names, vouches := listedOwners(t, s)
	if names[owner] != "Sam Ceremony" {
		t.Fatalf("ceremony owner not named: %v", names)
	}
	if vouches[owner].Signature != row.VouchSig {
		t.Fatal("the vouch was not returned for the owner's device to check")
	}
}

func TestACeremonyOwnerWhoseNameIsUnsignedOrWronglySignedIsNotNamed(t *testing.T) {
	const org, owner = "EORG", "EOWNER"
	seed := seedOf(7)
	key := keyOf(seed)
	cases := map[string]asset.Employee{
		"name edited after signing": vouchRow(t, seed, owner, org, "Sam", "Someone Else"),
		"signed by another key":     vouchRow(t, seedOf(9), owner, org, "Sam", "Sam"),
		"signed for another org":    vouchRow(t, seed, owner, "EOTHER", "Sam", "Sam"),
		"no vouch at all":           {PairwiseAID: owner, Name: "Sam", IsSigner: true},
	}
	for label, row := range cases {
		t.Run(label, func(t *testing.T) {
			s := anOrgWithOwners(t, []string{owner}, row)
			theEngineVerifies(s, owner, key)
			s.recordWhatNamesAnOwner(owner, anOwnersAddress(t, s, owner, key))
			if names, _ := listedOwners(t, s); names[owner] != "" {
				t.Fatalf("%s: a name was shown: %v", label, names)
			}
		})
	}
}

// A log that does not belong to the identifier the owner presented records
// nothing, so a name cannot be attached to someone else's key.
func TestALogForAnotherIdentifierIsNotRecorded(t *testing.T) {
	const org, owner = "EORG", "EOWNER"
	seed := seedOf(7)
	s := anOrgWithOwners(t, []string{owner}, vouchRow(t, seed, owner, org, "Sam", "Sam"))
	theEngineVerifies(s, "EOTHER", keyOf(seed))
	s.recordWhatNamesAnOwner(owner, anOwnersAddress(t, s, "EOTHER", keyOf(seed)))
	if names, _ := listedOwners(t, s); names[owner] != "" {
		t.Fatalf("named from a log that is not theirs: %v", names)
	}
}

// With an overlay owning the roster the core's own is empty; the overlay hands
// its roster over and gets exactly the names the core verifies.
func TestAnOverlaysRosterShowsTheSameVerifiedNames(t *testing.T) {
	const org, owner, impostor = "EORG", "EOWNER", "EIMPOSTOR"
	seed := seedOf(7)
	key := keyOf(seed)
	s := anOrgWithOwners(t, []string{owner, impostor}) // core roster empty
	theEngineVerifies(s, owner, key)
	s.recordWhatNamesAnOwner(owner, anOwnersAddress(t, s, owner, key))

	if names, _ := listedOwners(t, s); len(names) != 0 {
		t.Fatalf("no roster, yet names shown: %v", names)
	}
	good := vouchRow(t, seed, owner, org, "Sam Overlay", "Sam Overlay")
	bad := vouchRow(t, seed, impostor, org, "Mallory", "Mallory") // no verified log for them
	s.SetOwnerRoster(func() []asset.Employee { return []asset.Employee{good, bad} })

	names, _ := listedOwners(t, s)
	if names[owner] != "Sam Overlay" {
		t.Fatalf("overlay owner not named: %v", names)
	}
	if names[impostor] != "" {
		t.Fatalf("overlay got a name the core does not verify: %v", names)
	}
}
