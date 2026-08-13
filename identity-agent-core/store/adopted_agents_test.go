package store

import "testing"

// What an owner has to remember about a machine, and what it must not lose.
//
// Adoption used to write nothing down: the delegation went back to whoever
// asked and the owner kept no record, so an app that restarted knew nothing
// about a machine that knew exactly who owned it.

func adoptedStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAnAdoptedAgentIsRememberedAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdoptedAgent(AdoptedAgent{
		AID: "EBoxAID", SignsAsAID: "EDelegated", URL: "https://example/abc",
		Kind: "individual", Sealed: true, Measurement: "a45be582",
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// The point of the table: a new process finds the machine still there.
	again, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()

	got, err := again.ListAdoptedAgents()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("after a restart the owner listed %d agents, expected 1", len(got))
	}
	a := got[0]
	if a.SignsAsAID != "EDelegated" || a.URL != "https://example/abc" {
		t.Errorf("the record came back changed: %+v", a)
	}
	if !a.Sealed || a.Measurement != "a45be582" {
		t.Error("whether the machine proved itself, and what it was running, must survive — " +
			"asking the machine later means trusting what it says about itself")
	}
}

// Adopting the same machine twice is one machine, not two. Its address is the
// thing expected to change, so that is what an update carries.
func TestReadoptingTheSameMachineUpdatesItRatherThanDuplicating(t *testing.T) {
	s := adoptedStore(t)
	base := AdoptedAgent{AID: "EBoxAID", SignsAsAID: "EDelegated", URL: "https://old", Kind: "individual"}
	if err := s.SaveAdoptedAgent(base); err != nil {
		t.Fatal(err)
	}
	moved := base
	moved.URL = "https://new"
	if err := s.SaveAdoptedAgent(moved); err != nil {
		t.Fatal(err)
	}

	got, _ := s.ListAdoptedAgents()
	if len(got) != 1 {
		t.Fatalf("the same machine appears %d times", len(got))
	}
	if got[0].URL != "https://new" {
		t.Errorf("the address did not follow the machine: %s", got[0].URL)
	}
}

// A name somebody chose is not overwritten by a later adoption that carries
// none. Losing it would be a small thing that feels like the software forgot.
func TestALaterAdoptionDoesNotEraseAChosenName(t *testing.T) {
	s := adoptedStore(t)
	a := AdoptedAgent{AID: "EBoxAID", SignsAsAID: "EDel", URL: "https://x", Label: "Study machine"}
	if err := s.SaveAdoptedAgent(a); err != nil {
		t.Fatal(err)
	}
	unnamed := a
	unnamed.Label = ""
	if err := s.SaveAdoptedAgent(unnamed); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListAdoptedAgents()
	if got[0].Label != "Study machine" {
		t.Errorf("the name was lost: %q", got[0].Label)
	}
}

func TestAnAgentWithNoIdentifierIsRefused(t *testing.T) {
	s := adoptedStore(t)
	if err := s.SaveAdoptedAgent(AdoptedAgent{SignsAsAID: "EDel", URL: "https://x"}); err == nil {
		t.Fatal("an agent with no identifier was stored, so it could never be found again")
	}
}

// Forgetting is a local act. It removes the machine from this list and does not
// touch the delegation, which lives in a published log — so a caller must not
// be able to mistake one for the other.
func TestForgettingRemovesItFromTheListOnly(t *testing.T) {
	s := adoptedStore(t)
	if err := s.SaveAdoptedAgent(AdoptedAgent{AID: "EBoxAID", SignsAsAID: "EDel", URL: "https://x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetAdoptedAgent("EBoxAID"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListAdoptedAgents()
	if len(got) != 0 {
		t.Fatalf("still listed after being forgotten: %d", len(got))
	}
	// Forgetting one that was never there is not an error — the caller wanted
	// it gone and it is gone.
	if err := s.ForgetAdoptedAgent("ENeverExisted"); err != nil {
		t.Errorf("forgetting an unknown agent should be quiet: %v", err)
	}
}

func TestTheNewestAdoptionIsListedFirst(t *testing.T) {
	s := adoptedStore(t)
	for _, a := range []AdoptedAgent{
		{AID: "EOld", SignsAsAID: "D1", URL: "u1", AdoptedAt: "2026-01-01 10:00:00"},
		{AID: "ENew", SignsAsAID: "D2", URL: "u2", AdoptedAt: "2026-08-01 10:00:00"},
	} {
		if err := s.SaveAdoptedAgent(a); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.ListAdoptedAgents()
	if len(got) != 2 || got[0].AID != "ENew" {
		t.Errorf("somebody who just adopted a machine should see it first, got %+v", got)
	}
}

// The column rename must not lose what an already-installed agent recorded.
//
// Renaming a column in place is the one migration that can silently drop data
// if it runs against the wrong schema, and the value it carries here is the
// only record of what each paired machine signs as.
func TestRenamingTheColumnKeepsWhatWasAlreadyThere(t *testing.T) {
	s := adoptedStore(t)
	if err := s.SaveAdoptedAgent(AdoptedAgent{
		AID: "EPAIRWISE", SignsAsAID: "EMACHINEROOT", URL: "http://x",
		Kind: "individual", OwnerAID: "EOWNER", OwnerIndex: 2000001,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.ListAdoptedAgents()
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %v (%d rows)", err, len(got))
	}
	if got[0].SignsAsAID != "EMACHINEROOT" {
		t.Fatalf("what the machine signs as did not survive the rename: %q", got[0].SignsAsAID)
	}
	if got[0].OwnerAID != "EOWNER" || got[0].OwnerIndex != 2000001 {
		t.Fatal("the owner identity did not survive, so this machine could never be signed to again")
	}

	// Both names must not mean one thing. A surviving delegated_aid would let
	// new code read one column while old code writes the other.
	var name string
	err = s.db.QueryRow(
		`SELECT name FROM pragma_table_info('adopted_agents') WHERE name = 'delegated_aid'`,
	).Scan(&name)
	if err == nil {
		t.Fatal("delegated_aid is still present alongside signs_as_aid, so two column " +
			"names now mean the same thing and readers can disagree about which is current")
	}
}
