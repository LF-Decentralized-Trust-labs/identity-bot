package backup

import (
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/store"
)

func TestArchiveEncodeDecode(t *testing.T) {
	manifest := NewManifest("Etest", []string{TierCritical}, "full")
	arch := &ArchiveFile{
		Manifest:   manifest,
		Ciphertext: []byte{1, 2, 3, 4},
	}
	raw, err := EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeArchive(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Manifest.IdentityAID != "Etest" {
		t.Fatalf("aid mismatch: %s", dec.Manifest.IdentityAID)
	}
	if len(dec.Ciphertext) != 4 {
		t.Fatalf("ciphertext len %d", len(dec.Ciphertext))
	}
}

func TestLeanTier3NoBulkInArchive(t *testing.T) {
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	st, err := store.NewSQLiteStore(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// A large file the collector has never heard of. Carried even in lean
	// mode: the core cannot know what a build on top of it keeps on disk, and
	// losing somebody's data is the worse of the two problems. Size is the
	// easier one, and a delta backup omits what has not changed.
	aiPath := filepath.Join(dbDir, "some_large_store.db")
	bulk := make([]byte, 2*1024*1024)
	for i := range bulk {
		bulk[i] = byte(i % 256)
	}
	if err := os.WriteFile(aiPath, bulk, 0644); err != nil {
		t.Fatal(err)
	}

	collector := &Collector{DataDir: dbDir, Store: st}
	opts := CollectOptions{Tiers: []string{TierFull}}
	bundle, pointers, err := collector.Collect(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, carried := bundle.Sections["file:some_large_store.db"]; !carried {
		t.Fatal("a file on the device was not carried. The collector does not get to " +
			"decide it knows what matters")
	}
	if len(pointers) != 0 {
		t.Fatalf("nothing is pointed at any more, and a pointer names a path on the "+
			"device that just died: %+v", pointers)
	}
}

func TestOpenArchiveWrongPassphrase(t *testing.T) {
	bundle := &PayloadBundle{
		Ordered: []PayloadSection{{Name: "test", Data: []byte("hello")}},
	}
	plain, _ := SerializePayloadBundle(bundle)
	bek, _ := NewBEK()
	ct, nonce, _ := EncryptPayload(bek, plain)
	seedKEK, _ := SeedKEKFromMnemonic(testMnemonic)
	wrapped, wrapNonce, _ := WrapBEK(seedKEK, bek)
	manifest := NewManifest("", []string{TierCritical}, "full")
	manifest.PayloadNonceB64 = EncodeB64(nonce)
	manifest.KeySlots = []KeySlot{{
		Type: SlotSeedHD, WrappedBEKB64: EncodeB64(wrapped), NonceB64: EncodeB64(wrapNonce),
	}}
	manifest.Sections = []SectionMeta{{
		Name: "test", DigestBlake3QB64: DigestSectionMust([]byte("hello")), SizePlaintext: 5,
	}}
	raw, _ := EncodeArchive(&ArchiveFile{Manifest: manifest, Ciphertext: ct})

	_, _, err := OpenArchive(raw, OpenRequest{Mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"})
	if err == nil {
		t.Fatal("wrong mnemonic should fail")
	}
}

func TestRedundancyAndAntiDeadlockWarnings(t *testing.T) {
	w := RedundancyWarnings([]Destination{{Enabled: true}})
	if w == "" {
		t.Fatal("expected redundancy warning for single dest")
	}
	w2 := AntiDeadlockWarning([]Destination{{Enabled: true, IAGated: true}})
	if w2 == "" {
		t.Fatal("expected anti-deadlock warning")
	}
}
