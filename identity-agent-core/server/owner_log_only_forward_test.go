package server

import (
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/store"
)

const (
	forwardRetiredKey = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
	forwardCurrentKey = "DO1JKMYo0cLG6ukDOJBZlWEpWSc6XGP5NjbBRhSshzfR"
)

// An anchored machine whose owner key was sealed holds the owner's log only as
// a contact log. The log is the owner's whole history, cut at some point.
func anchoredWithSealed(t *testing.T, sealedKey string) *CoreServer {
	t.Helper()
	s := serverWithIdentity(t, "ETHING")
	s.KeriDriver = &driverfake.Engine{
		GetKelFunc: func(string) (*drivers.DriverKelResponse, error) {
			return &drivers.DriverKelResponse{AID: "ETHING", KEL: []map[string]interface{}{{
				"t": "icp", "i": "ETHING",
				"a": []interface{}{map[string]interface{}{"i": "EOWNER", "s": "0", "d": "EOWNER"}},
			}}}, nil
		},
	}
	if sealedKey != "" {
		if err := s.SealOwnerAuthority(OwnerAuthority{AID: "EOWNER", PublicKey: sealedKey}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func saveOwnerLog(t *testing.T, s *CoreServer, keys ...string) {
	t.Helper()
	var kel []map[string]interface{}
	for i, k := range keys {
		typ := "rot"
		if i == 0 {
			typ = "icp"
		}
		kel = append(kel, map[string]interface{}{"t": typ, "i": "EOWNER", "k": []interface{}{k}})
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: "EOWNER", KEL: kel, KelVerified: true, CurrentPublicKey: keys[len(keys)-1],
	}); err != nil {
		t.Fatal(err)
	}
}

// The replay: the owner rotated retired -> current and the machine sealed the
// current key; a verified log cut before the rotation must not win.
func TestAReplayedPreRotationLogIsRefusedOnAnAnchoredMachine(t *testing.T) {
	s := anchoredWithSealed(t, forwardCurrentKey)
	saveOwnerLog(t, s, forwardRetiredKey)

	a, err := s.ownerAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey != forwardCurrentKey {
		t.Fatalf("owner key is %q: the retired key was accepted from a replayed log", a.PublicKey)
	}
}

// The genuine log, ending at or after the sealed key, is still followed.
func TestTheGenuineCurrentLogIsAccepted(t *testing.T) {
	s := anchoredWithSealed(t, forwardRetiredKey)
	saveOwnerLog(t, s, forwardRetiredKey, forwardCurrentKey)

	a, err := s.ownerAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey != forwardCurrentKey {
		t.Fatalf("owner key is %q, want the rotated key", a.PublicKey)
	}

	// And a log whose tip is the sealed key itself.
	s2 := anchoredWithSealed(t, forwardCurrentKey)
	saveOwnerLog(t, s2, forwardRetiredKey, forwardCurrentKey)
	if a, err := s2.ownerAuthority(); err != nil || a.PublicKey != forwardCurrentKey {
		t.Fatalf("got %v, %v", a, err)
	}
}

// Nothing sealed: nothing to be behind, so the log answers as before. An
// unanchored machine is untouched.
func TestWithNothingSealedTheLogStillAnswersAndUnanchoredIsUnchanged(t *testing.T) {
	s := anchoredWithSealed(t, "")
	saveOwnerLog(t, s, forwardRetiredKey, forwardCurrentKey)
	if a, err := s.ownerAuthority(); err != nil || a.PublicKey != forwardCurrentKey {
		t.Fatalf("got %v, %v", a, err)
	}

	u := serverWithIdentity(t, "EPERSONAL")
	if err := u.SealOwnerAuthority(OwnerAuthority{AID: "EOWNER", PublicKey: forwardCurrentKey}); err != nil {
		t.Fatal(err)
	}
	saveOwnerLog(t, u, forwardRetiredKey)
	if a, err := u.ownerAuthority(); err != nil || a.PublicKey != forwardCurrentKey {
		t.Fatalf("unanchored: got %v, %v", a, err)
	}
}

// The same rule holds on the other two routes that ask which key speaks for the
// owner: who may vouch for a controller, and who signs the owner's name.
func TestAReplayedLogDoesNotLetARetiredKeyVouchOrSignTheOwnersName(t *testing.T) {
	s := anchoredWithSealed(t, forwardCurrentKey)
	saveOwnerLog(t, s, forwardRetiredKey)

	if key, err := s.theKeyEntitledToVouch(); err != nil || key != forwardCurrentKey {
		t.Fatalf("vouching key is %q (%v): the retired key was accepted from a replayed log", key, err)
	}
	if key := s.keyToCheckAnOwnersNameAgainst("EOWNER"); key != forwardCurrentKey {
		t.Fatalf("owner-name key is %q: the retired key was accepted from a replayed log", key)
	}
}
