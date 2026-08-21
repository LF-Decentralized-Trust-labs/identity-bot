package recovery

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/store"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func TestRestoreWrongSeedFails(t *testing.T) {
	archive := buildTestArchive(t, testMnemonic, nil)

	_, err := RestoreFromArchive(archive, OpenRequest{
		Mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
	})
	if err == nil {
		t.Fatal("wrong seed must fail archive open")
	}
}

func TestRestoreValidSeedPassesIntegrity(t *testing.T) {
	seed, err := backup.MnemonicToBIP39Seed(testMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := DerivePairwiseAtIndex(seed, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	contacts := []ContactPairwiseExpectation{{
		ContactRecord: store.ContactRecord{
			AID:       "Econtact00000000000000000000000000001",
			Alias:     "Alice",
			PublicKey: NormalizePublicKeyB64(pub),
			Status:    "accepted",
		},
	}}
	archive := buildTestArchive(t, testMnemonic, contacts)

	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if payload.Identity == nil || payload.Identity.AID != "EtestRecoveryAID" {
		t.Fatalf("identity aid mismatch: %+v", payload.Identity)
	}
	if len(payload.Contacts) != 1 {
		t.Fatalf("contacts len %d", len(payload.Contacts))
	}
}

func buildTestArchive(t *testing.T, mnemonic string, contacts []ContactPairwiseExpectation) []byte {
	t.Helper()
	return buildTestArchiveWith(t, mnemonic, contacts, nil)
}

// buildTestArchiveWith builds one carrying extra sections, so a test can put
// something in the archive that a recovering device would otherwise never see.
func buildTestArchiveWith(t *testing.T, mnemonic string,
	contacts []ContactPairwiseExpectation, extra map[string][]byte) []byte {
	t.Helper()

	identity := store.IdentityState{
		AID:           "EtestRecoveryAID",
		PublicKey:     "dGVzdA==",
		NextKeyDigest: "digest",
		Created:       "2026-01-01T00:00:00Z",
		EventCount:    1,
	}
	idJSON, _ := json.Marshal(identity)
	contactsJSON, _ := json.Marshal(contacts)

	bundle := &backup.PayloadBundle{
		Ordered: []backup.PayloadSection{
			{Name: "identity_state", Data: idJSON},
			{Name: "contacts", Data: contactsJSON},
		},
		Sections: map[string][]byte{
			"identity_state": idJSON,
			"contacts":       contactsJSON,
		},
	}
	for k, v := range extra {
		bundle.Sections[k] = v
		bundle.Ordered = append(bundle.Ordered, backup.PayloadSection{Name: k, Data: v})
	}

	plain, err := backup.SerializePayloadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bek, err := backup.NewBEK()
	if err != nil {
		t.Fatal(err)
	}
	ct, nonce, err := backup.EncryptPayload(bek, plain)
	if err != nil {
		t.Fatal(err)
	}

	seedKEK, err := backup.SeedKEKFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, wrapNonce, err := backup.WrapBEK(seedKEK, bek)
	if err != nil {
		t.Fatal(err)
	}

	manifest := backup.NewManifest("EtestRecoveryAID", []string{backup.TierCritical}, "full")
	manifest.PayloadNonceB64 = backup.EncodeB64(nonce)
	manifest.KeySlots = []backup.KeySlot{{
		Type: backup.SlotSeedHD, WrappedBEKB64: backup.EncodeB64(wrapped), NonceB64: backup.EncodeB64(wrapNonce),
	}}
	for _, sec := range bundle.Ordered {
		manifest.Sections = append(manifest.Sections, backup.SectionMeta{
			Name:             sec.Name,
			DigestBlake3QB64: backup.DigestSectionMust(sec.Data),
			SizePlaintext:    len(sec.Data),
		})
	}

	// Marked with who wrote it, the way a real archive is. Hand-built archives
	// that skip this are exactly what a substituted one looks like, and a
	// restore refuses them — so leaving it out would mean every test here
	// exercised a shape no real archive has.
	arch := &backup.ArchiveFile{Manifest: manifest, Ciphertext: ct}
	seed, err := backup.MnemonicToBIP39Seed(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.SignWithSeed(arch, seed); err != nil {
		t.Fatal(err)
	}

	raw, err := backup.EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPairwiseAIDFromPublicKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub := backup.PairwisePublicKey(seed)
	aid := PairwiseAIDFromPublicKey(pub)
	if len(aid) < 2 || aid[0] != 'E' {
		t.Fatalf("unexpected aid %q", aid)
	}
}
