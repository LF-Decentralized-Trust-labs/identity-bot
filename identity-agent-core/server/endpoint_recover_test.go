package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/store"
)

// verifiedLog is a stored log that was checked end to end.
func aVerifiedStoredLog(kel []map[string]interface{}) *store.ContactKELRecord {
	return &store.ContactKELRecord{KelVerified: true, KEL: kel}
}

// Witnesses to ask are chosen only from a log that was verified.
func TestWitnessesAreOnlyReadFromAVerifiedLog(t *testing.T) {
	kel := []map[string]interface{}{
		storedEvent(map[string]interface{}{"t": "icp", "s": "0", "b": []interface{}{"EWit"}}),
	}
	if got := witnessesFromStoredKEL(&store.ContactKELRecord{KelVerified: false, KEL: kel}); len(got) != 0 {
		t.Fatalf("an unverified log named %v", got)
	}
	if got := witnessesFromStoredKEL(nil); len(got) != 0 {
		t.Fatalf("no log named %v", got)
	}
}

// storedEvent is an event as a resolved contact's log keeps it: the bytes it
// was published as, base64, and nothing the sender wrote beside them.
func storedEvent(ev map[string]interface{}) map[string]interface{} {
	raw, _ := json.Marshal(ev)
	return map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signature": "x"}
}

// The witness list comes out of the KEL already on disk. That is what makes
// recovery possible at all: nothing here needs the address that just died.
func TestWitnessesComeFromTheStoredInception(t *testing.T) {
	kel := []map[string]interface{}{
		storedEvent(map[string]interface{}{"t": "icp", "s": "0", "b": []interface{}{"EWitOne", "EWitTwo"}}),
	}
	got := witnessesFromStoredKEL(aVerifiedStoredLog(kel))
	if len(got) != 2 || got[0] != "EWitOne" || got[1] != "EWitTwo" {
		t.Fatalf("expected both witnesses from the inception event, got %v", got)
	}
}

// A field the sender wrote beside the bytes decides nothing: only the bytes
// were checked.
func TestWitnessesAreNotTakenFromTextBesideTheBytes(t *testing.T) {
	entry := storedEvent(map[string]interface{}{"t": "icp", "s": "0", "b": []interface{}{"EReal"}})
	entry["b"] = []interface{}{"EPlanted"}
	entry["event_json"] = `{"t":"icp","b":["EPlanted"]}`
	got := witnessesFromStoredKEL(aVerifiedStoredLog([]map[string]interface{}{entry}))
	if len(got) != 1 || got[0] != "EReal" {
		t.Fatalf("witnesses must come from the verified bytes, got %v", got)
	}
}

// A rotation cuts and adds witnesses (br and ba), so the set in force is what
// the walk of the log leaves, not whatever the last event mentioned. Using the
// inception forever would send recovery to operators the contact has since left.
func TestARotationCutsAndAddsWitnesses(t *testing.T) {
	kel := []map[string]interface{}{
		storedEvent(map[string]interface{}{"t": "icp", "s": "0", "b": []interface{}{"EOldWit", "EKept"}}),
		storedEvent(map[string]interface{}{"t": "ixn", "s": "1"}),
		storedEvent(map[string]interface{}{"t": "rot", "s": "2", "br": []interface{}{"EOldWit"}, "ba": []interface{}{"ENewWitA"}}),
	}
	got := witnessesFromStoredKEL(aVerifiedStoredLog(kel))
	if len(got) != 2 || got[0] != "EKept" || got[1] != "ENewWitA" {
		t.Fatalf("a rotation should cut br and add ba, got %v", got)
	}
}

// An interaction event says nothing about witnesses, and a rotation that cuts
// every one of them leaves none. Conflating them would keep querying operators
// a contact deliberately dropped.
func TestAnInteractionLeavesTheSetAndACutEmptiesIt(t *testing.T) {
	silent := witnessesFromStoredKEL(aVerifiedStoredLog([]map[string]interface{}{
		storedEvent(map[string]interface{}{"t": "icp", "s": "0", "b": []interface{}{"EWit"}}),
		storedEvent(map[string]interface{}{"t": "ixn", "s": "1"}),
	}))
	if len(silent) != 1 {
		t.Errorf("an interaction event should not disturb the witness set, got %v", silent)
	}

	cleared := witnessesFromStoredKEL(aVerifiedStoredLog([]map[string]interface{}{
		storedEvent(map[string]interface{}{"t": "icp", "s": "0", "b": []interface{}{"EWit"}}),
		storedEvent(map[string]interface{}{"t": "rot", "s": "1", "br": []interface{}{"EWit"}}),
	}))
	if len(cleared) != 0 {
		t.Errorf("a rotation cutting every witness should clear the set, got %v", cleared)
	}
}

// An entry with no bytes cannot be believed, so it names no witness.
func TestAnEntryWithoutBytesNamesNoWitness(t *testing.T) {
	if got := witnessesFromStoredKEL(aVerifiedStoredLog([]map[string]interface{}{{"t": "icp", "s": "0", "b": []interface{}{"EWit"}}})); len(got) != 0 {
		t.Fatalf("a bare entry named %v", got)
	}
}

func TestWitnessBaseURLStripsTheOOBIPath(t *testing.T) {
	for in, want := range map[string]string{
		"https://wit.example.test/public/oobi/EWit": "https://wit.example.test",
		"https://wit.example.test/":                 "https://wit.example.test",
		"https://wit.example.test":                  "https://wit.example.test",
	} {
		if got := witnessBaseURL(in); got != want {
			t.Errorf("witnessBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// Recovery needs a contact resolved at least once. First contact genuinely
// requires a working address, and saying so is better than a confusing failure
// further down.
func TestRecoveryNeedsAContactSeenBefore(t *testing.T) {
	s := witnessWithStore(t)
	if _, err := s.RecoverContactEndpoint("ENeverSeen"); err == nil {
		t.Fatal("expected recovery to refuse a contact with no stored KEL")
	}
}

// The witnesses to ask are named by a log kept as verified. A stored log that
// is not verified is text somebody served, so it does not say who to ask.
func TestRecoveryDoesNotReadTheWitnessesFromAnUnverifiedLog(t *testing.T) {
	s := witnessWithStore(t)
	asked := false
	witness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = true
		json.NewEncoder(w).Encode(map[string]any{"records": []map[string]any{}})
	}))
	defer witness.Close()
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: "EContact", KelVerified: false,
		KEL: []map[string]interface{}{{"t": "icp", "s": "0", "b": []interface{}{"EWitOne"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveContact(store.ContactRecord{
		AID: "EWitOne", OobiURL: witness.URL + "/public/oobi/EWitOne",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecoverContactEndpoint("EContact"); err == nil || asked {
		t.Fatalf("a witness named by an unverified log was asked (err=%v, asked=%v)", err, asked)
	}
}

// The keys a peer is checked against are read from a verified log only.
func TestStoredKELEventsAreOnlyAVerifiedLog(t *testing.T) {
	s := witnessWithStore(t)
	for aid, verified := range map[string]bool{"EVerified": true, "EUnverified": false} {
		if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
			AID: aid, KelVerified: verified,
			KEL: withTheBytesItWasVerifiedBy(t, map[string]interface{}{"t": "icp", "s": "0", "i": aid, "d": aid}),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.storedKELEvents("EVerified")) != 1 {
		t.Fatal("a verified log was not read")
	}
	if got := s.storedKELEvents("EUnverified"); len(got) != 0 {
		t.Fatalf("an unverified log was read: %v", got)
	}
}
