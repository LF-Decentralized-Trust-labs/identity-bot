package backup

import (
	"strings"
	"testing"
)

// These tests exist because the format could declare AND long before anything
// enforced it. An archive that says two factors are required and opens with
// one is worse than an archive that never claimed it — the owner acted on the
// claim.

func andArchive(t *testing.T, passphrase string, sealTo ...[]byte) *ExportResult {
	t.Helper()
	collector := testCollector(t)
	result, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{
			Bundle:           testBundle(),
			Mnemonic:         testMnemonic,
			Passphrase:       passphrase,
			SlotPolicy:       PolicyAND,
			SealToPublicKeys: sealTo,
		},
	)
	if err != nil {
		t.Fatalf("create AND archive: %v", err)
	}
	return result
}

// The phrase is one factor. On its own it must not be enough — this is the
// exact case that used to succeed.
func TestAndArchiveDoesNotOpenWithTheKeyAlone(t *testing.T) {
	result := andArchive(t, "correct horse battery staple")

	if _, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: testMnemonic}); err == nil {
		t.Fatal("an archive requiring two factors opened with only the phrase")
	}
}

// And the passphrase on its own must not be enough either, which is the
// subtler half: it would be, if the passphrase still had a slot of its own.
func TestAndArchiveDoesNotOpenWithThePassphraseAlone(t *testing.T) {
	result := andArchive(t, "correct horse battery staple")

	_, _, err := OpenArchive(result.Bytes, OpenRequest{Passphrase: "correct horse battery staple"})
	if err == nil {
		t.Fatal("an archive requiring two factors opened with only the passphrase")
	}

	// Belt and braces: no passphrase slot may carry anything openable.
	for _, slot := range result.Manifest.KeySlots {
		if slot.Type == SlotPassphrase && slot.WrappedBEKB64 != "" {
			t.Fatal("the passphrase slot still holds a key, so the passphrase is a way in rather than a second lock")
		}
	}
}

func TestAndArchiveOpensWithBothFactors(t *testing.T) {
	result := andArchive(t, "correct horse battery staple")

	bundle, _, err := OpenArchive(result.Bytes, OpenRequest{
		Mnemonic:   testMnemonic,
		Passphrase: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("both factors failed to open the archive: %v", err)
	}
	if len(bundle.Ordered) != 1 || string(bundle.Ordered[0].Data) != "the quick brown fox" {
		t.Fatal("recovered payload does not match what was archived")
	}
}

// A wrong passphrase must fail at the second layer rather than anywhere that
// could be mistaken for the archive being corrupt.
func TestAndArchiveRejectsTheWrongPassphrase(t *testing.T) {
	result := andArchive(t, "correct horse battery staple")

	_, _, err := OpenArchive(result.Bytes, OpenRequest{
		Mnemonic:   testMnemonic,
		Passphrase: "not the passphrase",
	})
	if err == nil {
		t.Fatal("the wrong passphrase opened the archive")
	}
	if !strings.Contains(err.Error(), "second layer") {
		t.Fatalf("the failure does not say which factor was wrong: %v", err)
	}
}

// An AND archive with no second factor would be an OR archive wearing a label,
// so it must be refused at creation rather than written and believed.
func TestAndArchiveWithoutAPassphraseIsRefused(t *testing.T) {
	collector := testCollector(t)
	_, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{Bundle: testBundle(), Mnemonic: testMnemonic, SlotPolicy: PolicyAND},
	)
	if err == nil {
		t.Fatal("an AND archive was created with only one factor")
	}
	if !strings.Contains(err.Error(), "second factor") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// Opening without supplying a passphrase at all must say what is missing,
// rather than reporting that no slot unlocked.
func TestOpeningAnAndArchiveWithNoPassphraseSaysSo(t *testing.T) {
	result := andArchive(t, "correct horse battery staple")

	_, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: testMnemonic, Passphrase: ""})
	if err == nil {
		t.Fatal("opened with no passphrase")
	}
	if !strings.Contains(err.Error(), "requires a passphrase") {
		t.Fatalf("the error does not name what is missing: %v", err)
	}
}

// AND has to compose with per-owner sealed slots: every owner still needs the
// passphrase, and no owner is special.
func TestAndAppliesToEverySealedOwner(t *testing.T) {
	owners := []string{testMnemonic, secondMnemonic, thirdMnemonic}
	var pubs [][]byte
	for _, m := range owners {
		_, pub := sealKeysFor(t, m)
		pubs = append(pubs, pub)
	}

	collector := testCollector(t)
	result, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{
			Bundle:           testBundle(),
			Passphrase:       "shared company passphrase",
			SlotPolicy:       PolicyAND,
			SealToPublicKeys: pubs,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for i, m := range owners {
		if _, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: m}); err == nil {
			t.Fatalf("owner %d opened a two-factor archive alone", i)
		}
		if _, _, err := OpenArchive(result.Bytes, OpenRequest{
			Mnemonic:   m,
			Passphrase: "shared company passphrase",
		}); err != nil {
			t.Fatalf("owner %d could not open with both factors: %v", i, err)
		}
	}

	// An outsider with the passphrase is still an outsider.
	if _, _, err := OpenArchive(result.Bytes, OpenRequest{
		Mnemonic:   outsiderMnemonic,
		Passphrase: "shared company passphrase",
	}); err == nil {
		t.Fatal("somebody who owns nothing opened the archive by knowing the passphrase")
	}
}

// The default must not change. An archive that does not ask for AND keeps
// behaving exactly as it did, including the passphrase being a second door.
func TestOrRemainsTheDefaultAndKeepsWorking(t *testing.T) {
	collector := testCollector(t)
	result, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{
			Bundle:     testBundle(),
			Mnemonic:   testMnemonic,
			Passphrase: "a passphrase",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.SlotPolicy == PolicyAND {
		t.Fatal("AND was applied without being asked for")
	}
	if _, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("the phrase alone stopped working under OR: %v", err)
	}
	if _, _, err := OpenArchive(result.Bytes, OpenRequest{Passphrase: "a passphrase"}); err != nil {
		t.Fatalf("the passphrase alone stopped working under OR: %v", err)
	}
}

// Combining is order-sensitive and domain-separated, so the same two factors
// cannot accidentally produce a key used for anything else.
func TestCombiningFactorsIsOrderSensitive(t *testing.T) {
	a, _ := NewBEK()
	b, _ := NewBEK()

	ab, err := CombineFactors(a, b)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := CombineFactors(b, a)
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) == string(ba) {
		t.Fatal("swapping the factors produced the same key, so the order carries no meaning")
	}
	if _, err := CombineFactors(a[:16], b); err == nil {
		t.Fatal("a short factor was accepted")
	}
}
