package server

import (
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/store"
)

// An anchored machine whose owner key was sealed holds the owner's log only as
// a contact log. The log is the owner's whole history, cut at some point. The
// owner's identity is a real signed log, so what is stored is what the engine
// verifies and the store seals from its bytes.
func anchoredWithSealed(t *testing.T, owner string, sealedKey string) *CoreServer {
	t.Helper()
	s := serverWithIdentity(t, "ETHING")
	s.KeriDriver = &driverfake.Engine{
		GetKelFunc: func(string) (*drivers.DriverKelResponse, error) {
			return &drivers.DriverKelResponse{AID: "ETHING", KEL: []map[string]interface{}{{
				"t": "icp", "i": "ETHING",
				"a": []interface{}{map[string]interface{}{"i": owner, "s": "0", "d": owner}},
			}}}, nil
		},
	}
	if sealedKey != "" {
		if err := s.SealOwnerAuthority(OwnerAuthority{AID: owner, PublicKey: sealedKey}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// saveOwnerLog stores a signed log the way a verified resolve does.
func saveOwnerLog(t *testing.T, s *CoreServer, l *signedlog.Log) {
	t.Helper()
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: l.AID, KEL: l.Records(), KelVerified: true, CurrentPublicKey: l.Key(), EventsValidated: l.Len(),
	}); err != nil {
		t.Fatal(err)
	}
}

// The replay: the owner rotated K1 -> K2 and the machine sealed K2; a verified
// log cut before the rotation must not win, even on a machine that holds no
// longer log for the store to protect.
func TestAReplayedPreRotationLogIsRefusedOnAnAnchoredMachine(t *testing.T) {
	keys := signedlog.NewKeys(t, 2)
	atK1 := signedlog.Incept(t, keys)
	s := anchoredWithSealed(t, atK1.AID, keys.Pub(1))
	saveOwnerLog(t, s, atK1)

	a, err := s.ownerAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey != keys.Pub(1) {
		t.Fatalf("owner key is %q: the retired key was accepted from a replayed log", a.PublicKey)
	}
	// And the same question through the vouching route.
	if k, err := s.theKeyEntitledToVouch(); err != nil || k != keys.Pub(1) {
		t.Fatalf("vouching key is %q, %v", k, err)
	}
}

// The genuine log, ending at or after the sealed key, is still followed.
func TestTheGenuineCurrentLogIsAccepted(t *testing.T) {
	keys := signedlog.NewKeys(t, 2)
	atK1 := signedlog.Incept(t, keys)
	atK2 := atK1.Fork().Rotate()

	s := anchoredWithSealed(t, atK1.AID, keys.Pub(0))
	saveOwnerLog(t, s, atK2)
	if a, err := s.ownerAuthority(); err != nil || a.PublicKey != keys.Pub(1) {
		t.Fatalf("owner key is %v, %v, want the rotated key", a, err)
	}

	// And a log whose tip is the sealed key itself.
	s2 := anchoredWithSealed(t, atK1.AID, keys.Pub(1))
	saveOwnerLog(t, s2, atK2)
	if a, err := s2.ownerAuthority(); err != nil || a.PublicKey != keys.Pub(1) {
		t.Fatalf("got %v, %v", a, err)
	}
}

// Nothing sealed: nothing to be behind, so the log answers as before. An
// unanchored machine is untouched.
func TestWithNothingSealedTheLogStillAnswersAndUnanchoredIsUnchanged(t *testing.T) {
	keys := signedlog.NewKeys(t, 2)
	atK1 := signedlog.Incept(t, keys)
	atK2 := atK1.Fork().Rotate()

	s := anchoredWithSealed(t, atK1.AID, "")
	saveOwnerLog(t, s, atK2)
	if a, err := s.ownerAuthority(); err != nil || a.PublicKey != keys.Pub(1) {
		t.Fatalf("got %v, %v", a, err)
	}

	u := serverWithIdentity(t, "EPERSONAL")
	if err := u.SealOwnerAuthority(OwnerAuthority{AID: atK1.AID, PublicKey: keys.Pub(1)}); err != nil {
		t.Fatal(err)
	}
	saveOwnerLog(t, u, atK1)
	if a, err := u.ownerAuthority(); err != nil || a.PublicKey != keys.Pub(1) {
		t.Fatalf("unanchored: got %v, %v", a, err)
	}
}
