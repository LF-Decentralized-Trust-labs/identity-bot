package recovery

import (
	"bytes"
	"slices"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// Does my data come back?
//
// This is the property the whole of backup and recovery exists to deliver, and
// until now nothing asserted it. What was proven was the envelope: that an
// archive encrypts, that the wrong key fails, that the words alone open one.
// All true, all necessary, and none of it says the CONTENTS survive.
//
// So this does the only thing that answers the question. It puts real data into
// a real agent, takes a real archive to a real file, restores it onto a
// DIFFERENT device with nothing of its own, and compares what came back to what
// went in — item by item, not by counting.

// anAgentWithRealDataInIt builds a device holding the kinds of thing a person
// would be devastated to lose.
func anAgentWithRealDataInIt(t *testing.T) (dir string, st *store.SQLiteStore, seed []byte) {
	t.Helper()
	dir = t.TempDir()

	seed = make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	if err := secureenclave.StoreRootSeed(dir, seed); err != nil {
		t.Fatalf("seed the device: %v", err)
	}

	var err error
	st, err = store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.SaveIdentity(store.IdentityState{
		AID:             "EMyIdentityThatMustSurvive",
		PublicKey:       "DMyKey",
		DerivationIndex: 0,
		KeyGeneration:   0,
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []store.ContactRecord{
		{AID: "EAFriend", Alias: "a friend", Status: "accepted"},
		{AID: "EAnother", Alias: "somebody else", Status: "accepted"},
	} {
		if err := st.SaveContact(c); err != nil {
			t.Fatal(err)
		}
	}
	return dir, st, seed
}

// restoreOntoAnotherDevice takes a real encrypted archive of the given agent and
// restores it onto a device with nothing of its own — which is the situation
// somebody is actually in when this matters.
func restoreOntoAnotherDevice(t *testing.T, oldDir string, oldStore *store.SQLiteStore) (string, *store.SQLiteStore) {
	t.Helper()

	seed, err := secureenclave.LoadRootSeed(oldDir)
	if err != nil {
		t.Fatalf("read the seed: %v", err)
	}

	// Both tiers, because that is the shipped default.
	tiers := []string{backup.TierCritical, backup.TierImportant}
	c := &backup.Collector{DataDir: oldDir, Store: oldStore}
	archive, err := c.CreateArchive(
		backup.CollectOptions{Tiers: tiers},
		backup.ExportRequest{BIP39Seed: seed, Tiers: tiers},
	)
	if err != nil {
		t.Fatalf("create the archive: %v", err)
	}

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	t.Cleanup(func() { newStore.Close() })

	payload, err := RestoreFromArchive(archive.Bytes, OpenRequest{BIP39Seed: seed})
	if err != nil {
		t.Fatalf("the archive did not open on the new device: %v", err)
	}
	svc := &Service{DataDir: newDir, Store: newStore}
	if err := svc.applyPayload(payload); err != nil {
		t.Fatalf("restore: %v", err)
	}
	return newDir, newStore
}

// THE TEST. Everything else in this area is a component of it.
func TestMyDataComesBack(t *testing.T) {
	oldDir, oldStore, seed := anAgentWithRealDataInIt(t)

	// What went in, read back from the source of truth rather than assumed.
	wantIdentity, err := oldStore.GetIdentity()
	if err != nil || wantIdentity == nil {
		t.Fatalf("the old device has no identity to lose: %v", err)
	}
	wantContacts, err := oldStore.GetContacts()
	if err != nil {
		t.Fatal(err)
	}
	if len(wantContacts) == 0 {
		t.Fatal("the old device has no contacts, so this would prove nothing")
	}

	// A real archive, encrypted, as a real file.
	// Both tiers, because that is the shipped default — and because contacts
	// live in tier 2, so a tier-1 archive would prove nothing about them.
	tiers := []string{backup.TierCritical, backup.TierImportant}
	c := &backup.Collector{DataDir: oldDir, Store: oldStore}
	archive, err := c.CreateArchive(
		backup.CollectOptions{Tiers: tiers},
		backup.ExportRequest{BIP39Seed: seed, Tiers: tiers},
	)
	if err != nil {
		t.Fatalf("create the archive: %v", err)
	}

	// A DIFFERENT device, with nothing of its own — which is the situation
	// somebody is actually in.
	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	defer newStore.Close()

	payload, err := RestoreFromArchive(archive.Bytes, OpenRequest{BIP39Seed: seed})
	if err != nil {
		t.Fatalf("the archive did not open on the new device: %v", err)
	}
	svc := &Service{DataDir: newDir, Store: newStore}
	if err := svc.applyPayload(payload); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// --- and now the only question that matters ---

	gotIdentity, err := newStore.GetIdentity()
	if err != nil || gotIdentity == nil {
		t.Fatalf("the identity did not come back: %v", err)
	}
	if gotIdentity.AID != wantIdentity.AID {
		t.Fatalf("a different identity came back: %q, was %q", gotIdentity.AID, wantIdentity.AID)
	}
	if gotIdentity.PublicKey != wantIdentity.PublicKey {
		t.Errorf("the identity came back with a different key: %q, was %q",
			gotIdentity.PublicKey, wantIdentity.PublicKey)
	}

	gotContacts, err := newStore.GetContacts()
	if err != nil {
		t.Fatal(err)
	}
	// Compared by identifier, not by counting. A count matches while the
	// contents are wrong, and that is precisely the failure worth catching.
	byAID := map[string]store.ContactRecord{}
	for _, c := range gotContacts {
		byAID[c.AID] = c
	}
	for _, want := range wantContacts {
		got, ok := byAID[want.AID]
		if !ok {
			t.Errorf("contact %s (%s) did not come back", want.AID, want.Alias)
			continue
		}
		if got.Alias != want.Alias {
			t.Errorf("contact %s came back as %q, was %q", want.AID, got.Alias, want.Alias)
		}
	}

	reseated, err := secureenclave.LoadRootSeed(newDir)
	if err != nil || !bytes.Equal(reseated, seed) {
		t.Fatalf("the seed did not come back, so nothing on this device can sign: %v", err)
	}
}

// What was collected is what can be restored.
//
// A section can be collected, encrypted, digested and shipped, and then dropped
// on the floor by the restore path — every check passes and the archive is
// genuinely valid. Nothing that inspects an archive can catch that; only
// restoring one and looking at what arrived.
//
// This asserts the gap explicitly rather than leaving it to be discovered by
// somebody who needed the data.
func TestEverySectionCollectedIsAlsoRestored(t *testing.T) {
	oldDir, oldStore, _ := anAgentWithRealDataInIt(t)

	// One real item in each of the sections that used to be dropped, so the
	// check below is "did this come back", not "is this name on a list".
	// A hand-maintained list of what restores is the same failure it is
	// meant to catch, one level up.
	if err := oldStore.SaveCredential(store.CredentialRecord{
		SAID: "EMyCredentialThatMustSurvive", IssuerAID: "EIssuer",
		HolderAID: "EHolder", SchemaSAID: "ESchema",
		AcdcJson: `{"v":"ACDC10JSON"}`, Status: "issued", Format: "acdc",
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	if err := oldStore.SaveSettings(store.SettingsData{
		TunnelProvider: "cloudflare", TunnelDomain: "must-survive.example",
	}); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	if err := oldStore.SavePendingRequest(store.PendingRequest{
		AID: "EPendingThatMustSurvive", Alias: "someone waiting",
		PublicKey: "DKey", ReceivedAt: "2026-08-13T00:00:00Z",
	}); err != nil {
		t.Fatalf("save pending request: %v", err)
	}

	newDir, newStore := restoreOntoAnotherDevice(t, oldDir, oldStore)
	_ = newDir

	creds, err := newStore.GetCredentials()
	if err != nil {
		t.Fatalf("credentials after restore: %v", err)
	}
	if !slices.ContainsFunc(creds, func(c store.CredentialRecord) bool {
		return c.SAID == "EMyCredentialThatMustSurvive"
	}) {
		t.Errorf("the credential was backed up and did not come back: got %d credentials", len(creds))
	}

	settings, err := newStore.GetSettings()
	if err != nil {
		t.Fatalf("settings after restore: %v", err)
	}
	if settings == nil || settings.TunnelDomain != "must-survive.example" {
		t.Errorf("settings were backed up and did not come back: %+v", settings)
	}

	pending, err := newStore.GetPendingRequests()
	if err != nil {
		t.Fatalf("pending requests after restore: %v", err)
	}
	if !slices.ContainsFunc(pending, func(p store.PendingRequest) bool {
		return p.AID == "EPendingThatMustSurvive"
	}) {
		t.Errorf("the pending request was backed up and did not come back: got %d", len(pending))
	}
}

// Anything collected that no restore path reads is carried across and then
// discarded. This is the tripwire for a section added months from now: it
// fails on the new name rather than on the day somebody needed the data.
func TestNoSectionIsCollectedAndThenIgnored(t *testing.T) {
	dir, st, _ := anAgentWithRealDataInIt(t)

	c := &backup.Collector{DataDir: dir, Store: st}
	bundle, _, err := c.Collect(backup.DefaultCollectOptions(
		[]string{backup.TierCritical, backup.TierImportant}))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	consumed := map[string]bool{
		// Read back as raw sections by applyPayload.
		"login_relationships": true,
		"root_seed":           true,
		"sqlite_identity_db":  true,
		"credentials":         true,
		"settings":            true,
		"pending_requests":    true,
		// Parsed into typed fields by RestoreFromArchive and applied from there.
		"identity_state": true,
		"kel_events":     true,
		"contacts":       true,
	}

	var dropped []string
	for name := range bundle.Sections {
		if !consumed[name] {
			dropped = append(dropped, name)
		}
	}
	slices.Sort(dropped)
	if len(dropped) > 0 {
		t.Errorf("these sections are backed up and never restored: %v\n"+
			"They are collected, encrypted, digested and shipped, and no restore "+
			"path reads them. The archive is valid; the data is gone.", dropped)
	}
}
