package backup

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// Standard BIP39 test vectors, standing in for different people: two further
// owners, and somebody who owns nothing.
const (
	secondMnemonic   = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	thirdMnemonic    = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
	outsiderMnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
)

func seedFor(t *testing.T, mnemonic string) []byte {
	t.Helper()
	seed, err := MnemonicToBIP39Seed(mnemonic, "")
	if err != nil {
		t.Fatalf("seed from mnemonic: %v", err)
	}
	return seed
}

func sealKeysFor(t *testing.T, mnemonic string) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := DeriveSealKeypair(seedFor(t, mnemonic))
	if err != nil {
		t.Fatalf("derive seal keypair: %v", err)
	}
	return priv, pub
}

// The same phrase must always produce the same sealing key, or an archive
// sealed today could not be opened by the same words tomorrow.
func TestSealKeypairIsDeterministic(t *testing.T) {
	priv1, pub1 := sealKeysFor(t, testMnemonic)
	priv2, pub2 := sealKeysFor(t, testMnemonic)

	if !bytes.Equal(priv1, priv2) || !bytes.Equal(pub1, pub2) {
		t.Fatal("the same seed produced a different sealing keypair on a second derivation")
	}
	if _, otherPub := sealKeysFor(t, secondMnemonic); bytes.Equal(pub1, otherPub) {
		t.Fatal("two different seeds produced the same sealing key")
	}
}

// The sealing key must not be reachable from the other keys derived from the
// same seed. If it were, a component trusted with one of those would silently
// gain the ability to read backups.
func TestSealKeyIsSeparateFromTheOtherSeedKeys(t *testing.T) {
	seed := seedFor(t, testMnemonic)
	priv, _ := sealKeysFor(t, testMnemonic)

	backupKEK, err := DeriveBackupKEK(seed)
	if err != nil {
		t.Fatal(err)
	}
	vaultKEK, err := DeriveVaultKEK(seed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(priv, backupKEK) || bytes.Equal(priv, vaultKEK) {
		t.Fatal("the sealing key collides with another key derived from the same seed")
	}
}

func TestSealAndUnsealRoundTrip(t *testing.T) {
	priv, pub := sealKeysFor(t, testMnemonic)
	bek, _ := NewBEK()

	ephPub, wrapped, nonce, err := SealBEK(pub, bek)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := UnsealBEK(priv, ephPub, wrapped, nonce)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !bytes.Equal(got, bek) {
		t.Fatal("unsealed key does not match the sealed one")
	}
}

// Somebody else's key must fail closed rather than return anything, because
// trying every slot in turn is how a multi-owner archive is opened.
func TestUnsealWithTheWrongKeyFails(t *testing.T) {
	_, pub := sealKeysFor(t, testMnemonic)
	otherPriv, _ := sealKeysFor(t, secondMnemonic)
	bek, _ := NewBEK()

	ephPub, wrapped, nonce, err := SealBEK(pub, bek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnsealBEK(otherPriv, ephPub, wrapped, nonce); err == nil {
		t.Fatal("an unrelated private key opened the slot")
	}
}

// Sealing twice to the same recipient must not produce the same bytes, or an
// observer could tell that two archives carry the same backup key.
func TestSealingTwiceProducesDifferentSlots(t *testing.T) {
	_, pub := sealKeysFor(t, testMnemonic)
	bek, _ := NewBEK()

	eph1, wrapped1, _, err := SealBEK(pub, bek)
	if err != nil {
		t.Fatal(err)
	}
	eph2, wrapped2, _, err := SealBEK(pub, bek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(eph1, eph2) {
		t.Fatal("the ephemeral key was reused between two seals")
	}
	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatal("two seals of the same key produced identical ciphertext")
	}
}

func testBundle() *PayloadBundle {
	return &PayloadBundle{
		Ordered: []PayloadSection{{Name: "test", Data: []byte("the quick brown fox")}},
	}
}

func testCollector(t *testing.T) *Collector {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Collector{DataDir: dir, Store: st}
}

// The property this whole change exists for: an agent that has never been told
// the phrase produces an archive, and the phrase alone opens it.
func TestExportWithoutASeedIsOpenedByThePhraseAlone(t *testing.T) {
	_, pub := sealKeysFor(t, testMnemonic)
	collector := testCollector(t)

	result, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{
			// No mnemonic and no seed — exactly what a rented machine has.
			Bundle:           testBundle(),
			SealToPublicKeys: [][]byte{pub},
		},
	)
	if err != nil {
		t.Fatalf("export without a seed: %v", err)
	}

	for _, slot := range result.Manifest.KeySlots {
		if slot.Type == SlotSeedHD {
			t.Fatal("a seed slot was written even though no seed was supplied")
		}
	}

	bundle, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatalf("the phrase alone failed to open the archive: %v", err)
	}
	if len(bundle.Ordered) != 1 || string(bundle.Ordered[0].Data) != "the quick brown fox" {
		t.Fatal("recovered payload does not match what was archived")
	}
}

// An archive with no way in at all must be refused at the point of creation,
// not discovered to be useless on the day it is needed.
func TestExportWithNoUnlockPathIsRefused(t *testing.T) {
	collector := testCollector(t)
	_, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{Bundle: testBundle()},
	)
	if err == nil {
		t.Fatal("an archive nobody could open was created")
	}
	if !strings.Contains(err.Error(), "no way to unlock") {
		t.Fatalf("unhelpful error for an unopenable archive: %v", err)
	}
}

// One organisation, three owners: each opens the archive alone, and an
// outsider cannot. This is the backup half of the ownership model — every
// owner may read the company's data without assembling a quorum.
func TestEveryOwnerCanOpenAndAnOutsiderCannot(t *testing.T) {
	owners := []string{testMnemonic, secondMnemonic, thirdMnemonic}
	var pubs [][]byte
	for _, m := range owners {
		_, pub := sealKeysFor(t, m)
		pubs = append(pubs, pub)
	}

	collector := testCollector(t)
	result, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{Bundle: testBundle(), SealToPublicKeys: pubs},
	)
	if err != nil {
		t.Fatal(err)
	}

	for i, m := range owners {
		if _, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: m}); err != nil {
			t.Fatalf("owner %d could not open the archive alone: %v", i, err)
		}
	}

	if _, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: outsiderMnemonic}); err == nil {
		t.Fatal("somebody who is not an owner opened the archive")
	}
}

// The manifest is not encrypted, so anything named in it is disclosed to
// whoever holds the archive. An organisation's owners must not be.
func TestTheManifestNamesNoRecipient(t *testing.T) {
	var pubs [][]byte
	for _, m := range []string{testMnemonic, secondMnemonic} {
		_, pub := sealKeysFor(t, m)
		pubs = append(pubs, pub)
	}

	collector := testCollector(t)
	result, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{Bundle: testBundle(), SealToPublicKeys: pubs},
	)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(result.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for i, pub := range pubs {
		if bytes.Contains(encoded, []byte(EncodeB64(pub))) {
			t.Fatalf("the manifest discloses owner %d's public key", i)
		}
	}

	sealed := 0
	for _, slot := range result.Manifest.KeySlots {
		if slot.Type == SlotSealedX25519 {
			sealed++
		}
	}
	if sealed != len(pubs) {
		t.Fatalf("expected %d sealed slots, got %d", len(pubs), sealed)
	}
}

// Both routes in must work on the same archive: the phrase for the owner, and
// a seed slot for the paths that still supply one.
func TestSeedAndSealedSlotsCoexist(t *testing.T) {
	_, pub := sealKeysFor(t, secondMnemonic)
	collector := testCollector(t)

	result, err := collector.CreateArchive(
		CollectOptions{Tiers: []string{TierCritical}},
		ExportRequest{
			Bundle:           testBundle(),
			Mnemonic:         testMnemonic,
			SealToPublicKeys: [][]byte{pub},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("the seed slot did not open: %v", err)
	}
	if _, _, err := OpenArchive(result.Bytes, OpenRequest{Mnemonic: secondMnemonic}); err != nil {
		t.Fatalf("the sealed slot did not open: %v", err)
	}
}
