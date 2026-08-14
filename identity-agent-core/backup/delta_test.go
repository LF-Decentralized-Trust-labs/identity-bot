package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/store"
)

func TestDeltaRoundtrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	svc := NewService(dir, st)
	opts := DefaultCollectOptions([]string{TierCritical, TierImportant})

	collector := svc.Collector()
	full1, ptrs, err := collector.Collect(opts)
	if err != nil {
		t.Fatal(err)
	}

	ds := ResetDeltaState()
	if err := UpdateDeltaStateAfterBackup(&ds, full1, SnapshotFull, false); err != nil {
		t.Fatal(err)
	}

	fullResult, err := collector.CreateArchive(opts, ExportRequest{
		Mnemonic:             testMnemonic,
		SnapshotType:         SnapshotFull,
		Bundle:               full1,
		ExternalPointers:     ptrs,
		DeltaStateDigestQB64: ds.ChainDigestQB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fullResult.SnapshotType != SnapshotFull {
		t.Fatalf("expected full snapshot, got %s", fullResult.SnapshotType)
	}

	if ds.ChainDigestQB64 == "" {
		t.Fatal("expected chain digest after full backup")
	}
	if err := ds.VerifyChain(); err != nil {
		t.Fatal(err)
	}
	if fullResult.Manifest.DeltaStateDigestQB64 != ds.ChainDigestQB64 {
		t.Fatal("manifest must pin delta state digest")
	}

	opened, manifest, err := OpenArchive(fullResult.Bytes, OpenRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SnapshotType != SnapshotFull {
		t.Fatal("opened manifest snapshot type mismatch")
	}
	if len(opened.Ordered) == 0 {
		t.Fatal("expected sections in full archive")
	}

	// Mutate tier2 data and build delta archive.
	if err := st.SaveSettings(store.SettingsData{TunnelProvider: "grapeid"}); err != nil {
		t.Fatal(err)
	}
	full2, ptrs2, err := collector.Collect(opts)
	if err != nil {
		t.Fatal(err)
	}
	deltaBundle := FilterDeltaBundle(full2, &ds, opts.Tiers)
	if len(deltaBundle.Ordered) == 0 {
		t.Fatal("expected delta sections after profile change")
	}

	pending := ds
	if err := UpdateDeltaStateAfterBackup(&pending, full2, SnapshotDelta, false); err != nil {
		t.Fatal(err)
	}
	deltaResult, err := collector.CreateArchive(opts, ExportRequest{
		Mnemonic:             testMnemonic,
		SnapshotType:         SnapshotDelta,
		Bundle:               deltaBundle,
		ExternalPointers:     ptrs2,
		DeltaStateDigestQB64: pending.ChainDigestQB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if deltaResult.SnapshotType != SnapshotDelta {
		t.Fatalf("expected delta snapshot, got %s", deltaResult.SnapshotType)
	}

	deltaOpened, deltaManifest, err := OpenArchive(deltaResult.Bytes, OpenRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if deltaManifest.SnapshotType != SnapshotDelta {
		t.Fatal("delta manifest type mismatch")
	}
	hasTier1 := false
	hasSettings := false
	for _, sec := range deltaOpened.Ordered {
		if sec.Name == "settings" {
			hasSettings = true
		}
		if sec.Name == "identity_state" || sec.Name == "kel_events" {
			hasTier1 = true
		}
	}
	if !hasTier1 || !hasSettings {
		t.Fatal("delta archive should include tier1 and changed tier2 sections")
	}
}

func TestDeltaMismatchFailsafe(t *testing.T) {
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	svc := NewService(dir, st)
	collector := svc.Collector()
	opts := DefaultCollectOptions([]string{TierCritical})

	full, _, err := collector.Collect(opts)
	if err != nil {
		t.Fatal(err)
	}
	ds := ResetDeltaState()
	if err := UpdateDeltaStateAfterBackup(&ds, full, SnapshotFull, false); err != nil {
		t.Fatal(err)
	}
	ds.ChainDigestQB64 = "EMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := svc.ConfigStore.SaveDeltaState(ds); err != nil {
		t.Fatal(err)
	}

	snapshotType, reset := DecideSnapshotType(ds, string(EventCredential), false)
	if snapshotType != SnapshotFull || !reset {
		t.Fatalf("expected full snapshot with chain reset, got %s reset=%v", snapshotType, reset)
	}

	cfg := DefaultConfig()
	cfg.Enabled = true
	if err := svc.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExportWithReason(testMnemonic, "", filepath.Join(dir, "failover.iab"), opts.Tiers, string(EventCredential))
	if err != nil {
		t.Fatal(err)
	}
	if result.SnapshotType != SnapshotFull {
		t.Fatalf("fail-safe export must be full, got %s", result.SnapshotType)
	}
	saved, err := svc.ConfigStore.LoadDeltaState()
	if err != nil {
		t.Fatal(err)
	}
	if err := saved.VerifyChain(); err != nil {
		t.Fatal("rebuilt chain must verify after fail-safe full snapshot")
	}
}

func TestLeanTier3StillWorksAfterDeltaChanges(t *testing.T) {
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

	bulkPath := filepath.Join(dbDir, "some_large_store.db")
	bulk := make([]byte, 1024)
	if err := os.WriteFile(bulkPath, bulk, 0644); err != nil {
		t.Fatal(err)
	}

	collector := &Collector{DataDir: dbDir, Store: st}
	opts := CollectOptions{Tiers: []string{TierFull}, LeanTier3: true}
	bundle, pointers, err := collector.Collect(opts)
	if err != nil {
		t.Fatal(err)
	}
	carried := false
	for _, sec := range bundle.Ordered {
		if strings.HasPrefix(sec.Name, FileSectionPrefix) {
			carried = true
		}
	}
	if !carried {
		t.Fatal("a full backup carried no files from the device at all")
	}
	ds := ResetDeltaState()
	if err := UpdateDeltaStateAfterBackup(&ds, bundle, SnapshotFull, false); err != nil {
		t.Fatal(err)
	}
	deltaBundle := FilterDeltaBundle(bundle, &ds, opts.Tiers)
	for _, sec := range deltaBundle.Ordered {
		if strings.HasPrefix(sec.Name, FileSectionPrefix) || strings.HasPrefix(sec.Name, "sandbox_") {
			t.Fatalf("unchanged tier3 lean data must not appear in delta, got %s", sec.Name)
		}
	}
	if len(deltaBundle.Ordered) == 0 {
		t.Fatal("delta should still include unchanged tier1 sections")
	}
	// Carrying a device's files does not mean carrying them every time: a
	// delta leaves out what has not changed, so the cost of a large file lands
	// on full backups rather than on all of them.
	_ = pointers
}

// Every archive carries the key, including one that carries nothing else new.
//
// The seed is the one thing that never changes, so a rule of "include what
// changed" left it out of every delta — and a delta is what the scheduler
// produces most days. Somebody restoring from their most recent backup would
// have found an archive that opens, contains their data, and cannot sign
// anything, because there was no key in it.
func TestADeltaStillCarriesTheKey(t *testing.T) {
	c := &Collector{DataDir: t.TempDir()}
	full := &PayloadBundle{Sections: map[string][]byte{}, Ordered: []PayloadSection{}}
	c.addRawSection(full, "root_seed", []byte("the key everything derives from"))
	c.addRawSection(full, "identity_state", []byte(`{"aid":"EAnIdentity"}`))
	c.addRawSection(full, "contacts", []byte(`[{"aid":"EAFriend"}]`))

	ds := ResetDeltaState()
	if err := UpdateDeltaStateAfterBackup(&ds, full, SnapshotFull, false); err != nil {
		t.Fatal(err)
	}

	// The ordinary case: a scheduled backup on a day nothing changed.
	delta := FilterDeltaBundle(full, &ds, []string{TierCritical, TierImportant, TierFull})

	if _, ok := delta.Sections["root_seed"]; !ok {
		t.Fatal("a delta backup carries no key material, so restoring from it " +
			"produces an identity that cannot sign anything")
	}
	if _, ok := delta.Sections["contacts"]; ok {
		t.Error("unchanged bulk data should still be left out — that is what a delta is for")
	}
}
