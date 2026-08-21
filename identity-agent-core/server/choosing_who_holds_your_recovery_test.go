package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setWhoHolds(t *testing.T, s *CoreServer, body string) (int, whoHoldsYourRecovery) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/recovery/who-holds-this",
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	s.handleSetWhoHoldsYourRecovery(rec, req)
	var out whoHoldsYourRecovery
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// A choice that could never be satisfied is refused when it is made.
//
// Asking for three shares from two holders does not protect an owner from an
// attacker; it protects the identity from its owner, and the worst moment to
// find that out is the one moment they need it.
func TestAChoiceThatCouldNeverBeSatisfiedIsRefusedWhenItIsMade(t *testing.T) {
	s := agentWithNoIdentity(t)
	code, _ := setWhoHolds(t, s, `{"needed":3,"holders":[
		{"id":"EOne","kind":"device","public_key_b64":"AA=="},
		{"id":"ETwo","kind":"device","public_key_b64":"BB=="}]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("a threshold larger than the holder count was accepted (%d)", code)
	}
}

// A passphrase cannot be the only thing beside the words.
func TestAPassphraseAloneIsRefusedHere(t *testing.T) {
	s := agentWithNoIdentity(t)
	code, _ := setWhoHolds(t, s, `{"needed":1,"holders":[
		{"id":"Epass","kind":"passphrase","public_key_b64":"AA=="}]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("a backup protected only by a passphrase was accepted (%d)", code)
	}
}

// What the choice costs is answered by the core, in the same words for both
// apps, and it is answered even when the choice is a good one.
func TestTheCoreSaysWhatTheChoiceCosts(t *testing.T) {
	s := agentWithNoIdentity(t)

	// Nothing chosen: the words alone, and what that means.
	code, off := setWhoHolds(t, s, `{"needed":0,"holders":[]}`)
	if code != http.StatusOK {
		t.Fatalf("turning it off answered %d", code)
	}
	if !strings.Contains(off.SayThis, "words alone") {
		t.Fatalf("it does not say what no protection means: %q", off.SayThis)
	}

	// A threshold of one: one thing to lose rather than several.
	_, one := setWhoHolds(t, s, `{"needed":1,"holders":[
		{"id":"EPhone","kind":"device","public_key_b64":"AA=="}]}`)
	if !strings.Contains(one.SayThis, "single one") {
		t.Fatalf("a threshold of one was not called out: %q", one.SayThis)
	}

	// All devices: a fire takes the lot, so ask for a person.
	_, devices := setWhoHolds(t, s, `{"needed":2,"holders":[
		{"id":"EPhone","kind":"device","public_key_b64":"AA=="},
		{"id":"ELaptop","kind":"device","public_key_b64":"BB=="}]}`)
	if !strings.Contains(devices.SayThis, "person you trust") {
		t.Fatalf("every share on a device was not called out: %q", devices.SayThis)
	}

	// And a good choice still says what was given up.
	_, good := setWhoHolds(t, s, `{"needed":2,"holders":[
		{"id":"EPhone","kind":"device","public_key_b64":"AA=="},
		{"id":"EFriend","kind":"witness","public_key_b64":"BB=="}]}`)
	if good.SayThis == "" {
		t.Fatal("a correct choice said nothing about the words no longer being enough")
	}
	if !strings.Contains(good.SayThis, "no longer enough") {
		t.Fatalf("it does not say what was given up: %q", good.SayThis)
	}
}

// The choice is stored, because a scheduled backup runs when nobody is there.
func TestTheChoiceOutlivesTheScreenItWasMadeOn(t *testing.T) {
	s := agentWithNoIdentity(t)
	if code, _ := setWhoHolds(t, s, `{"needed":2,"holders":[
		{"id":"EPhone","kind":"device","public_key_b64":"AA=="},
		{"id":"EFriend","kind":"witness","public_key_b64":"BB=="}]}`); code != http.StatusOK {
		t.Fatalf("saving answered %d", code)
	}

	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Split.Needed != 2 || len(cfg.Split.Holders) != 2 {
		t.Fatalf("the choice did not reach the configuration a scheduled backup reads: %+v",
			cfg.Split)
	}

	// And reading it back gives the same answer plus the consequence.
	rec := httptest.NewRecorder()
	s.handleGetWhoHoldsYourRecovery(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	var got whoHoldsYourRecovery
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Needed != 2 || len(got.Holders) != 2 || got.SayThis == "" {
		t.Fatalf("reading it back gave %+v", got)
	}
}

// Turning it off is a real answer, not a failure.
func TestSomebodyCanChooseTheWordsAlone(t *testing.T) {
	s := agentWithNoIdentity(t)
	setWhoHolds(t, s, `{"needed":1,"holders":[
		{"id":"EPhone","kind":"device","public_key_b64":"AA=="}]}`)

	if code, _ := setWhoHolds(t, s, `{"needed":0,"holders":[]}`); code != http.StatusOK {
		t.Fatalf("turning it off answered %d, so the setting is one-way", code)
	}
	cfg, _ := s.backupService().LoadConfig()
	if len(cfg.Split.Holders) != 0 {
		t.Fatal("turning it off left holders behind")
	}
}
