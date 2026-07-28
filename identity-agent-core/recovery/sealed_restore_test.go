package recovery

import (
	"encoding/json"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/store"
)

const (
	ownerMnemonic    = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	strangerMnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
)

// sealedArchiveFor builds an archive the way an agent that has never held the
// seed would build one: a random backup key sealed to a public key, and no
// seed slot at all.
func sealedArchiveFor(t *testing.T, mnemonics ...string) []byte {
	t.Helper()

	var pubs [][]byte
	for _, m := range mnemonics {
		seed, err := backup.MnemonicToBIP39Seed(m, "")
		if err != nil {
			t.Fatal(err)
		}
		pub, err := backup.DeriveSealPublicKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, pub)
	}

	identity, err := json.Marshal(store.IdentityState{
		AID:        "EAtestidentityaidforsealedrestore",
		PublicKey:  "DAtestpublickeyforsealedrestore",
		Created:    "2026-07-28T00:00:00Z",
		EventCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	collector := &backup.Collector{DataDir: t.TempDir()}
	result, err := collector.CreateArchive(
		backup.CollectOptions{Tiers: []string{backup.TierCritical}},
		backup.ExportRequest{
			Bundle: &backup.PayloadBundle{
				Ordered: []backup.PayloadSection{{Name: "identity_state", Data: identity}},
			},
			SealToPublicKeys: pubs,
		},
	)
	if err != nil {
		t.Fatalf("sealed export: %v", err)
	}
	return result.Bytes
}

// The whole round trip, end to end: an agent with no seed writes the archive,
// and the words alone bring the identity back. Nothing else is supplied —
// no sealing key, no passphrase, no knowledge that sealing was used at all.
func TestRestoreSealedArchiveFromThePhraseAlone(t *testing.T) {
	archive := sealedArchiveFor(t, ownerMnemonic)

	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: ownerMnemonic})
	if err != nil {
		t.Fatalf("restore from the phrase alone: %v", err)
	}
	if payload.Identity == nil {
		t.Fatal("no identity came back from the archive")
	}
	if payload.Identity.AID != "EAtestidentityaidforsealedrestore" {
		t.Fatalf("wrong identity restored: %s", payload.Identity.AID)
	}
}

// Holding the archive must not be enough. This is the property that makes it
// safe to store backups somewhere the owner does not control.
func TestAStrangerCannotRestoreASealedArchive(t *testing.T) {
	archive := sealedArchiveFor(t, ownerMnemonic)

	if _, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: strangerMnemonic}); err == nil {
		t.Fatal("somebody else's phrase restored the archive")
	}
	if _, err := RestoreFromArchive(archive, OpenRequest{}); err == nil {
		t.Fatal("the archive was restored with no key at all")
	}
}

// An organisation's archive: two owners, either of whom can restore the
// company's data alone.
func TestEitherOwnerRestoresAnOrganisationArchive(t *testing.T) {
	owners := []string{ownerMnemonic, "legal winner thank year wave sausage worth useful legal winner thank yellow"}
	archive := sealedArchiveFor(t, owners...)

	for i, m := range owners {
		payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: m})
		if err != nil {
			t.Fatalf("owner %d could not restore alone: %v", i, err)
		}
		if payload.Identity == nil {
			t.Fatalf("owner %d restored an archive with no identity in it", i)
		}
	}
}
