package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/store"
)

// The owner's real history K1 -> K2 -> K3, and a fork of it that someone holding
// the retired K2 signed (events of their own after the K2 rotation), as long as
// the real one. The engine verifies both (drivers: TestAForkSignedByARetiredKeyIsVerifiedByTheEngine).
func theRealLogAndAForkOfIt(t *testing.T) (keys *signedlog.Keys, real, fork *signedlog.Log) {
	t.Helper()
	keys = signedlog.NewKeys(t, 3)
	atK2 := signedlog.Incept(t, keys).Rotate()
	real = atK2.Fork().Rotate()
	fork = atK2.Fork().Interact("mine").Interact("also mine")
	return
}

func holdVerified(t *testing.T, s *CoreServer, l *signedlog.Log) error {
	t.Helper()
	return s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: l.AID, KEL: l.Records(), KelVerified: true, CurrentPublicKey: l.Key(), EventsValidated: l.Len(),
	})
}

// The attack end to end for the owner's key: the machine sealed K1 and has since
// been shown the whole history (K3). The fork contains K1, so the forward-only
// rule alone would accept it; it must never get to replace the longer log.
func TestAForkAtARetiredKeyCannotMakeThatKeyTheOwner(t *testing.T) {
	keys, real, fork := theRealLogAndAForkOfIt(t)
	s := anchoredWithSealed(t, real.AID, keys.Pub(0))
	if err := holdVerified(t, s, real); err != nil {
		t.Fatal(err)
	}
	if err := holdVerified(t, s, fork); err == nil {
		t.Fatal("the fork replaced the log this machine holds")
	}
	if a, err := s.ownerAuthority(); err != nil || a.PublicKey != keys.Pub(2) {
		t.Fatalf("the owner key is %v, %v, want the current K3", a, err)
	}
}

// What this does NOT defend, pinned so it is not mistaken for covered: a machine
// that never held a log past K1 -> K2 and still has K1 sealed (the sealed point
// does not advance) accepts the K1..K2 replay, because it contains the sealed
// key and there is nothing held for it to extend.
func TestAMachineThatNeverHeldTheNewerLogAcceptsAK1ToK2Replay(t *testing.T) {
	keys, real, _ := theRealLogAndAForkOfIt(t)
	s := anchoredWithSealed(t, real.AID, keys.Pub(0))
	if err := holdVerified(t, s, real.Cut(2)); err != nil {
		t.Fatal(err)
	}
	if a, err := s.ownerAuthority(); err != nil || a.PublicKey != keys.Pub(1) {
		t.Fatalf("got %v, %v: the documented limit no longer holds, update the PR body", a, err)
	}
}

// A contact is re-checked from their address when their key is used. If the log
// served there is one the store refuses, the check fails and returns no key.
func TestARefusedLogFailsTheCheckAndHandsBackNoKey(t *testing.T) {
	keys, real, fork := theRealLogAndAForkOfIt(t)
	s := witnessWithSeed(t, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"kel": fork.Records()})
	}))
	t.Cleanup(srv.Close)
	s.KeriDriver = &driverfake.Engine{
		ValidateKELFunc: func(string, []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) {
			return &drivers.DriverValidateKELResponse{KelVerified: true, CurrentPublicKey: fork.Key(), EventsValidated: fork.Len()}, nil
		},
	}
	if err := s.DataStore.SaveContact(store.ContactRecord{AID: real.AID, PublicKey: keys.Pub(2), OobiURL: srv.URL + "/oobi/" + real.AID}); err != nil {
		t.Fatal(err)
	}
	if err := holdVerified(t, s, real); err != nil {
		t.Fatal(err)
	}

	got := s.checkContactKEL(real.AID)
	if got.State != kelFailed {
		t.Fatalf("a log the store refused checked as %q (key %q)", got.State, got.Key)
	}
	if got.Key != "" {
		t.Fatalf("the check handed back %q from a log the store refused", got.Key)
	}
	if held, _ := s.DataStore.GetContactKEL(real.AID); held == nil || held.CurrentPublicKey != keys.Pub(2) {
		t.Fatalf("the held log changed: %+v", held)
	}
}

// Resolving a contact's address saves the log before the duplicity watcher runs,
// so a refused save has to end the request there rather than report the key.
func TestResolvingALogTheStoreRefusesIsRefusedAndReportsNoKey(t *testing.T) {
	// The peer here is a local test server, which the owner allows in their own
	// environment (a stranger's address cannot).
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	keys, real, fork := theRealLogAndAForkOfIt(t)
	s := witnessWithSeed(t, 3)
	s.KeriDriver = &driverfake.Engine{
		ValidateKELFunc: func(string, []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) {
			return &drivers.DriverValidateKELResponse{KelVerified: true, CurrentPublicKey: fork.Key(), EventsValidated: fork.Len()}, nil
		},
		ValidateKELBytesFunc: func(drivers.ValidateKELInput) (*drivers.DriverValidateKELResponse, error) {
			return &drivers.DriverValidateKELResponse{KelVerified: true, CurrentPublicKey: fork.Key(), EventsValidated: fork.Len()}, nil
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": real.AID, "public_key": fork.Key(), "alias": "owner", "kel": fork.Records(),
		})
	}))
	t.Cleanup(srv.Close)
	if err := holdVerified(t, s, real); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"oobi_url": srv.URL + "/oobi/" + real.AID})
	rec := httptest.NewRecorder()
	s.handleResolveOobiContact(rec, httptest.NewRequest(http.MethodPost, "/api/contacts/resolve", bytes.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("resolving a refused log: %d %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(fork.Key())) || bytes.Contains(rec.Body.Bytes(), []byte(`"resolved"`)) {
		t.Fatalf("the refused log's key was reported: %s", rec.Body.String())
	}
	if held, _ := s.DataStore.GetContactKEL(real.AID); held == nil || held.CurrentPublicKey != keys.Pub(2) {
		t.Fatalf("the held log changed: %+v", held)
	}
}

// A seal that is there and cannot be read is not "nothing sealed". Reading it as
// that lets a verified log (here the retired K1's replay) decide the owner on a
// machine that has one.
func TestASealThatCannotBeReadIsNotTakenAsNothingSealed(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, path string){
		"the seal is not valid JSON": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"the seal cannot be opened as a file": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			keys := signedlog.NewKeys(t, 2)
			atK1 := signedlog.Incept(t, keys)
			s := anchoredWithSealed(t, atK1.AID, keys.Pub(1))
			saveOwnerLog(t, s, atK1) // the replay, which the intact seal refuses
			damage(t, filepath.Join(s.DataDir, ownerAuthorityFile))

			if a, err := s.ownerAuthority(); err == nil {
				t.Fatalf("an unreadable seal still named an owner key: %+v", a)
			}
			if k, err := s.theKeyEntitledToVouch(); err == nil {
				t.Fatalf("an unreadable seal still named a vouching key: %q", k)
			}
			if k, ok := s.ownerKeyThatMovesForward(atK1.AID); ok {
				t.Fatalf("an unreadable seal let a log answer: %q", k)
			}
		})
	}
}
