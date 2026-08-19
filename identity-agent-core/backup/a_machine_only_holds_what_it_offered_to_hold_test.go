package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The receiving side used to do whatever it was asked.
//
// POST /api/backup/receive is a PUBLIC route, so "whoever asked" is any host
// that can open a connection to an agent. It wrote the bytes it was given to a
// directory named after the identifier it was given, joined straight onto a
// path — so the caller chose the location as well as the contents — and it
// never looked at how much room was left.

func TestAnIdentifierCannotChooseWhereTheArchiveLands(t *testing.T) {
	// Each of these is a real path once joined onto a data directory.
	// filepath.Join CLEANS as it joins, so "../../.." does not stay a literal
	// directory name: it walks up and out.
	for _, notAnAID := range []string{
		"../../..",
		"../../../../etc",
		"a/../../b",
		"/etc/passwd",
		"..",
		".",
		"",
		strings.Repeat("A", 200),
	} {
		if err := AcceptableAID(notAnAID); err == nil {
			t.Fatalf("accepted %q as an identifier, so a caller could pick the directory", notAnAID)
		}
	}

	// And the shape a real one has, which must still work.
	good := "E" + strings.Repeat("A", 43)
	if err := AcceptableAID(good); err != nil {
		t.Fatalf("refused a well-formed AID: %v", err)
	}
	// Hyphen and underscore are in base64url and appear in real AIDs.
	withBoth := "E" + strings.Repeat("a", 20) + "-" + strings.Repeat("b", 21) + "_"
	if err := AcceptableAID(withBoth); err != nil {
		t.Fatalf("refused a base64url AID: %v", err)
	}
}

func TestTraversalWouldHaveEscapedTheDataDirectory(t *testing.T) {
	// Proves the attack was real rather than theoretical, by showing where the
	// unchecked join actually resolves to.
	escaped := filepath.Join("/data", "backup_receive", "../../../../etc")
	if !strings.HasPrefix(escaped, "/data") {
		// Expected: it is /etc. Nothing to assert beyond naming it.
		if escaped != "/etc" {
			t.Fatalf("expected the join to escape to /etc, got %s", escaped)
		}
	} else {
		t.Fatal("the join no longer escapes, so this test is describing something that changed")
	}
}

func TestAMachineThatNeverOfferedHoldsNothing(t *testing.T) {
	// The default, and what every existing installation decodes to.
	var never Offer // zero value, as an old config without the field would give
	err := never.MayAccept("E"+strings.Repeat("A", 43), false)
	if err == nil {
		t.Fatal("a machine that never volunteered accepted an archive")
	}
	if !strings.Contains(err.Error(), "has to offer that first") {
		t.Fatalf("refusal does not say why: %v", err)
	}

	if DefaultOffer().Accepting {
		t.Fatal("the default offer accepts archives, so upgrading turns it on for everyone")
	}
}

func TestStoppingNewIdentitiesDoesNotStopTheOnesAlreadyHere(t *testing.T) {
	// The distinction B6 turns on. Collapsing these two produces exactly the
	// failure the setting exists to prevent: somebody adds this machine, is
	// confirmed, and it silently holds nothing but the first archive.
	o := Offer{Accepting: true, AcceptingNewIdentities: false}
	aid := "E" + strings.Repeat("A", 43)

	if err := o.MayAccept(aid, true); err != nil {
		t.Fatalf("an identity already held here was refused its delta: %v", err)
	}

	err := o.MayAccept(aid, false)
	if err == nil {
		t.Fatal("a new identity was taken on while not accepting new identities")
	}
	// Refused at the moment it asks, so it can go and find another destination.
	if !strings.Contains(err.Error(), "not taking on new") {
		t.Fatalf("refusal does not say what is happening: %v", err)
	}
}

func TestAFullMachineSaysSoRatherThanAcceptingWhatItCannotStore(t *testing.T) {
	dir := t.TempDir()
	// A reserve larger than any disk, so the check must fire.
	o := Offer{Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1 << 62}
	err := o.RoomFor(dir, 1024)
	if err == nil {
		t.Fatal("accepted an archive with no room for it")
	}
	if !strings.Contains(err.Error(), "full") ||
		!strings.Contains(err.Error(), "earlier archives are untouched") {
		t.Fatalf("a full machine must say it is full AND that nothing was deleted: %v", err)
	}

	// And with a sane reserve it does not fire.
	sane := Offer{Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024}
	if err := sane.RoomFor(dir, 1024); err != nil {
		t.Fatalf("refused an archive that fits: %v", err)
	}
}

func TestWhatThisMachineHoldsIsMetadataAndNothingElse(t *testing.T) {
	root := t.TempDir()
	svc := &Service{DataDir: root}

	one := "E" + strings.Repeat("A", 43)
	two := "E" + strings.Repeat("B", 43)
	for aid, sizes := range map[string][]int{one: {100, 250}, two: {40}} {
		d := filepath.Join(root, "backup_receive", aid)
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		for i, n := range sizes {
			f := filepath.Join(d, string(rune('a'+i))+".iab")
			if err := os.WriteFile(f, make([]byte, n), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}

	// A directory whose name is not an AID can only predate the check. It must
	// not be listed — that would put an attacker's chosen string on a screen.
	if err := os.MkdirAll(filepath.Join(root, "backup_receive", "not-an-aid"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "backup_receive", "not-an-aid", "x.iab"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	held, err := svc.Held()
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 2 {
		t.Fatalf("expected two identities, got %d: %+v", len(held), held)
	}
	if held[0].IdentityAID != one || held[0].Archives != 2 || held[0].TotalBytes != 350 {
		t.Fatalf("wrong metadata for the first identity: %+v", held[0])
	}
	if held[1].Archives != 1 || held[1].TotalBytes != 40 {
		t.Fatalf("wrong metadata for the second identity: %+v", held[1])
	}
	for _, h := range held {
		if h.LastArrivedAt == "" {
			t.Fatalf("no arrival time, so a stalled backup would look healthy: %+v", h)
		}
	}
}

func TestRemovingWhatIsHeldIsDeliberateAndBounded(t *testing.T) {
	root := t.TempDir()
	svc := &Service{DataDir: root}
	aid := "E" + strings.Repeat("A", 43)
	d := filepath.Join(root, "backup_receive", aid)
	if err := os.MkdirAll(d, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "a.iab"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	// Something outside, which must survive whatever this does.
	outside := filepath.Join(root, "identity.db")
	if err := os.WriteFile(outside, []byte("important"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := svc.StopHoldingFor("../.."); err == nil {
		t.Fatal("a traversal reached a recursive delete")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("something outside backup_receive was deleted: %v", err)
	}

	if err := svc.StopHoldingFor(aid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Fatal("the archives were not removed")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("removing one identity took something else with it: %v", err)
	}
}
