package recovery

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// A holder standing on its own, answering over HTTP the way a friend's agent
// or somebody's phone would.
type aHolderOnTheNetwork struct {
	server   *httptest.Server
	holdings *Holdings
	holder   *Holder
	now      time.Time
}

func startAHolder(t *testing.T, policy HoldingPolicy) *aHolderOnTheNetwork {
	t.Helper()
	dir := t.TempDir()
	h := &aHolderOnTheNetwork{
		holdings: &Holdings{DataDir: dir},
		holder:   &Holder{DataDir: dir},
		now:      time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/recovery/share-requests", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IdentityAID string             `json:"identity_aid"`
			HolderID    string             `json:"holder_id"`
			Sealed      backup.SealedShare `json:"sealed_share"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		holding, err := h.holdings.Find(req.IdentityAID, req.HolderID)
		if err != nil || holding == nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"detail": "this share was not sealed to this holder"})
			return
		}
		share, err := h.holder.Release(*holding, req.Sealed, h.now)
		if err != nil {
			var held *ErrHeldForWait
			w.WriteHeader(http.StatusConflict)
			out := map[string]string{"detail": err.Error()}
			if asHeld(err, &held) {
				out["release_after"] = held.Until.UTC().Format(time.RFC3339)
			}
			json.NewEncoder(w).Encode(out)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"share_b64": backup.EncodeB64(share)})
	})

	h.server = httptest.NewServer(mux)
	t.Cleanup(h.server.Close)
	return h
}

func asHeld(err error, target **ErrHeldForWait) bool {
	h, ok := err.(*ErrHeldForWait)
	if ok {
		*target = h
	}
	return ok
}

// agreesToHold has this holder take on a share and hand back its public key.
func (h *aHolderOnTheNetwork) agreesToHold(t *testing.T, identityAID, holderID string, policy HoldingPolicy) backup.ShareHolder {
	t.Helper()
	agreed, err := h.holdings.Agree(AgreeToHold{
		IdentityAID: identityAID, HolderID: holderID, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return backup.ShareHolder{
		ID:           holderID,
		Kind:         "witness",
		PublicKeyB64: agreed.PublicKeyB64,
		Address:      h.server.URL,
		KnownAs:      identityAID,
	}
}

// The whole way round: three holders, a real archive, and real requests.
//
// Every other test here works on the pieces. This one takes an identity, backs
// it up so the words are not enough, and then recovers it by asking machines
// that each hold one key and one promise — which is the only arrangement that
// makes the second and third gates govern the data rather than only this
// software.
func TestAnIdentityComesBackFromTheWordsAndThreeHolders(t *testing.T) {
	const identityAID = "EPairwiseForThisBackup"

	// Three friends' agents, each generating its own key and never being told
	// the recovery words.
	a := startAHolder(t, HoldingPolicy{})
	b := startAHolder(t, HoldingPolicy{})
	c := startAHolder(t, HoldingPolicy{})
	holders := []backup.ShareHolder{
		a.agreesToHold(t, identityAID, "EFriendA", HoldingPolicy{}),
		b.agreesToHold(t, identityAID, "EFriendB", HoldingPolicy{}),
		c.agreesToHold(t, identityAID, "EFriendC", HoldingPolicy{}),
	}

	oldDir, oldStore := machineWithAnIdentity(t, "EMyIdentity")
	if err := oldStore.SaveContact(contactNamed("EAlice", "Alice")); err != nil {
		t.Fatal(err)
	}
	archive := archiveSplitAcross(t, oldDir, oldStore, holders, 2)
	oldStore.Close()

	// A machine that has never held any of this.
	env, _, err := backup.OpenBootstrap(archive, backup.OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatalf("the words did not open the envelope: %v", err)
	}
	if env == nil {
		t.Fatal("this archive was not written with a split")
	}

	shares, state, err := GatherShares(env, a.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Enough() {
		t.Fatalf("gathered %d of %d needed: %+v", state.Gathered, state.Needed, state.Holders)
	}

	bundle, _, err := backup.OpenArchive(archive, backup.OpenRequest{
		Mnemonic: testPhrase, Shares: shares,
	})
	if err != nil {
		t.Fatalf("the words and the gathered shares did not open it: %v", err)
	}
	if len(bundle.Sections["contacts"]) == 0 {
		t.Fatal("the identity's data did not come back")
	}
}

// A holder that is waiting does not end the recovery.
//
// This is what the threshold buys, and it is the case a list of requirements
// would fail: one holder waiting out its window, and the other two are enough.
func TestOneHolderWaitingDoesNotStopTheOthers(t *testing.T) {
	const identityAID = "EPairwiseForThisBackup"

	a := startAHolder(t, HoldingPolicy{})
	b := startAHolder(t, HoldingPolicy{})
	slow := startAHolder(t, HoldingPolicy{})
	holders := []backup.ShareHolder{
		a.agreesToHold(t, identityAID, "EFriendA", HoldingPolicy{}),
		b.agreesToHold(t, identityAID, "EFriendB", HoldingPolicy{}),
		// This one waits two days before it will release anything.
		slow.agreesToHold(t, identityAID, "ESlowFriend", HoldingPolicy{WaitHours: 48}),
	}

	oldDir, oldStore := machineWithAnIdentity(t, "EMyIdentity")
	archive := archiveSplitAcross(t, oldDir, oldStore, holders, 2)
	oldStore.Close()

	env, _, err := backup.OpenBootstrap(archive, backup.OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	shares, state, err := GatherShares(env, a.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Enough() {
		t.Fatalf("two willing holders were not enough: %+v", state.Holders)
	}
	if _, _, err := backup.OpenArchive(archive, backup.OpenRequest{
		Mnemonic: testPhrase, Shares: shares,
	}); err != nil {
		t.Fatalf("could not open it with the two that answered: %v", err)
	}

	// And the one that is waiting says when it expects to release, so a screen
	// can tell somebody to come back rather than that it failed.
	var slowState AskedAHolder
	for _, s := range state.Holders {
		if s.HolderID == "ESlowFriend" {
			slowState = s
		}
	}
	if slowState.Released {
		t.Fatal("a holder with a two-day wait released immediately")
	}
	if slowState.ReleaseAfter == "" {
		t.Fatalf("a waiting holder did not say when it would release: %+v", slowState)
	}
}

// Too few holders answering leaves the archive shut.
func TestNotEnoughHoldersLeavesItShut(t *testing.T) {
	const identityAID = "EPairwiseForThisBackup"

	a := startAHolder(t, HoldingPolicy{})
	slow1 := startAHolder(t, HoldingPolicy{})
	slow2 := startAHolder(t, HoldingPolicy{})
	holders := []backup.ShareHolder{
		a.agreesToHold(t, identityAID, "EFriendA", HoldingPolicy{}),
		slow1.agreesToHold(t, identityAID, "ESlowOne", HoldingPolicy{WaitHours: 48}),
		slow2.agreesToHold(t, identityAID, "ESlowTwo", HoldingPolicy{WaitHours: 48}),
	}

	oldDir, oldStore := machineWithAnIdentity(t, "EMyIdentity")
	archive := archiveSplitAcross(t, oldDir, oldStore, holders, 2)
	oldStore.Close()

	env, _, _ := backup.OpenBootstrap(archive, backup.OpenRequest{Mnemonic: testPhrase})
	shares, state, err := GatherShares(env, a.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if state.Enough() {
		t.Fatal("one holder satisfied a threshold of two")
	}
	_, _, err = backup.OpenArchive(archive, backup.OpenRequest{
		Mnemonic: testPhrase, Shares: shares,
	})
	if err == nil {
		t.Fatal("the archive opened without enough shares")
	}
}

// A holder that cannot be reached is an ordinary outcome, not a crash, and
// what a screen is told does not carry an address or an errno.
func TestAHolderThatCannotBeReachedIsJustOneThatDidNotAnswer(t *testing.T) {
	const identityAID = "EPairwiseForThisBackup"

	a := startAHolder(t, HoldingPolicy{})
	gone := startAHolder(t, HoldingPolicy{})
	holders := []backup.ShareHolder{
		a.agreesToHold(t, identityAID, "EFriendA", HoldingPolicy{}),
		gone.agreesToHold(t, identityAID, "EGoneFriend", HoldingPolicy{}),
	}
	gone.server.Close() // this friend's machine is off

	oldDir, oldStore := machineWithAnIdentity(t, "EMyIdentity")
	archive := archiveSplitAcross(t, oldDir, oldStore, holders, 1)
	oldStore.Close()

	env, _, _ := backup.OpenBootstrap(archive, backup.OpenRequest{Mnemonic: testPhrase})
	shares, state, err := GatherShares(env, a.server.Client())
	if err != nil {
		t.Fatalf("an unreachable holder ended the whole gathering: %v", err)
	}
	if !state.Enough() {
		t.Fatal("the reachable holder was not enough for a threshold of one")
	}
	if _, _, err := backup.OpenArchive(archive, backup.OpenRequest{
		Mnemonic: testPhrase, Shares: shares,
	}); err != nil {
		t.Fatal(err)
	}

	for _, s := range state.Holders {
		if s.HolderID != "EGoneFriend" {
			continue
		}
		for _, leak := range []string{"127.0.0.1", "http://", "connection refused", "dial tcp"} {
			if strings.Contains(strings.ToLower(s.Why), leak) {
				t.Fatalf("what a screen is told carries %q: %q", leak, s.Why)
			}
		}
	}
}

// Agreeing again gives back the same key, and never a new one.
//
// Two things have to be true at once, and an earlier version got one by
// breaking the other. Minting a second key silently orphans every share
// already sealed to the first, so every backup taken before today stops
// opening — but refusing the second agreement outright broke the ordinary
// case, because every backup after the first asks its holders again, and a
// refusal meant they were quietly dropped. The day-one story then worked
// exactly once.
func TestAgreeingAgainReturnsTheSameKey(t *testing.T) {
	h := startAHolder(t, HoldingPolicy{})
	first, err := h.holdings.Agree(AgreeToHold{IdentityAID: "EX", HolderID: "EMe"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := h.holdings.Agree(AgreeToHold{IdentityAID: "EX", HolderID: "EMe"})
	if err != nil {
		t.Fatalf("agreeing again was refused, which drops this holder from every later backup: %v", err)
	}
	if again.PublicKeyB64 != first.PublicKeyB64 {
		t.Fatal("agreeing again minted a second key and orphaned every share sealed to the first")
	}
}

// A backup taken later keeps the holders the first one had.
//
// The day-one story is that the machines somebody already has become the
// holders. That has to keep working on the second backup and the hundredth,
// and it did not: asking a machine that had already agreed was refused, the
// machine landed in "could not ask", and the archive was written without it.
func TestTheSecondBackupKeepsTheSameHolders(t *testing.T) {
	a := startAHoldingServer(t)
	b := startAHoldingServer(t)
	machines := []store.AdoptedAgent{{AID: "EPhone", URL: a.URL}, {AID: "ELaptop", URL: b.URL}}

	first, couldNotAsk := HoldersFromPairedMachines(machines, "EMyIdentity", HoldingPolicy{}, a.Client(), nil)
	if len(first) != 2 || len(couldNotAsk) != 0 {
		t.Fatalf("the first backup got %d holders, could not ask %v", len(first), couldNotAsk)
	}
	second, couldNotAsk := HoldersFromPairedMachines(machines, "EMyIdentity", HoldingPolicy{}, a.Client(), nil)
	if len(second) != 2 {
		t.Fatalf("the second backup got %d holders, could not ask %v", len(second), couldNotAsk)
	}
	// And the same keys, so an archive taken before still opens.
	for i := range first {
		if first[i].PublicKeyB64 != second[i].PublicKeyB64 {
			t.Fatalf("holder %s changed key between backups, so the earlier archive "+
				"can no longer be opened by it", first[i].ID)
		}
	}
}

// A holding file that cannot be read must not be treated as no holding.
func TestACorruptHoldingDoesNotMintASecondKey(t *testing.T) {
	h := startAHolder(t, HoldingPolicy{})
	if _, err := h.holdings.Agree(AgreeToHold{IdentityAID: "EX", HolderID: "EMe"}); err != nil {
		t.Fatal(err)
	}
	// The file is there and unreadable, which is not the same as absent.
	entries, _ := os.ReadDir(filepath.Join(h.holdings.DataDir, "shares_held"))
	if len(entries) != 1 {
		t.Fatalf("expected one holding on disk, found %d", len(entries))
	}
	path := filepath.Join(h.holdings.DataDir, "shares_held", entries[0].Name())
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := h.holdings.Agree(AgreeToHold{IdentityAID: "EX", HolderID: "EMe"}); err == nil {
		t.Fatal("a corrupt holding was treated as none, and a second key was minted — " +
			"silently orphaning every share sealed to the first")
	}
}

// What a holder lists never includes the key that makes it work.
func TestListingWhatIsHeldDoesNotHandOutTheKeys(t *testing.T) {
	h := startAHolder(t, HoldingPolicy{})
	if _, err := h.holdings.Agree(AgreeToHold{IdentityAID: "EX", HolderID: "EMe"}); err != nil {
		t.Fatal(err)
	}
	all, err := h.holdings.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected one holding, got %d", len(all))
	}
	if all[0].PrivateKeyB64 != "" {
		t.Fatal("listing what this machine holds handed out the private key")
	}
}

func contactNamed(aid, alias string) store.ContactRecord {
	return store.ContactRecord{AID: aid, Alias: alias}
}

// archiveSplitAcross backs an identity up so the words alone will not open it.
func archiveSplitAcross(t *testing.T, dir string, st store.Store,
	holders []backup.ShareHolder, needed int) []byte {
	t.Helper()
	c := &backup.Collector{DataDir: dir, Store: st}
	opts := backup.CollectOptions{Tiers: []string{backup.TierCritical, backup.TierImportant}}
	bundle, pointers, err := c.Collect(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.CreateArchive(opts, backup.ExportRequest{
		Mnemonic:         testPhrase,
		Tiers:            opts.Tiers,
		Bundle:           bundle,
		ExternalPointers: pointers,
		Split:            backup.HowTheWayInIsSplit{Needed: needed, Holders: holders},
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Bytes
}

// A holder is never told whose identity it is protecting.
//
// This is the point of addressing a recovery witness by an identifier made for
// that one relationship. Sending the identity's own AID would hand every
// holder — and anybody watching the request — the name of the identity they
// help protect, which is exactly what naming holders by a pairwise identifier
// exists to prevent. It would also make one person holding shares for two
// identities able to tell they were two.
//
// Found by a test that could not find its holding, which is the good version
// of finding this.
func TestAHolderIsNeverToldWhoseIdentityItProtects(t *testing.T) {
	const realAID = "EMyIdentity"
	const knownAs = "EPairwiseForThisOneRelationship"

	var sawInRequest []string
	friend := startAHolder(t, HoldingPolicy{})
	agreed, err := friend.holdings.Agree(AgreeToHold{
		IdentityAID: knownAs, HolderID: "EFriend",
	})
	if err != nil {
		t.Fatal(err)
	}

	// A server that records exactly what arrives.
	spy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if aid, ok := body["identity_aid"].(string); ok {
			sawInRequest = append(sawInRequest, aid)
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"detail": "not today"})
	}))
	defer spy.Close()

	env := &backup.WhatTheWordsOpen{
		IdentityAID: realAID,
		Split: backup.HowTheWayInIsSplit{
			Needed: 1,
			Holders: []backup.ShareHolder{{
				ID: "EFriend", Kind: "witness",
				PublicKeyB64: agreed.PublicKeyB64,
				Address:      spy.URL,
				KnownAs:      knownAs,
			}},
		},
		SealedShares: []backup.SealedShare{{HolderID: "EFriend"}},
	}

	GatherShares(env, spy.Client())

	if len(sawInRequest) != 1 {
		t.Fatalf("expected one request, saw %d", len(sawInRequest))
	}
	if sawInRequest[0] == realAID {
		t.Fatal("the holder was told the identity's own AID")
	}
	if sawInRequest[0] != knownAs {
		t.Fatalf("the holder was asked about %q rather than the identifier it knows", sawInRequest[0])
	}
}

// Day one: the machines somebody already has become the holders.
func TestThePairedMachinesBecomeHolders(t *testing.T) {
	a := startAHoldingServer(t)
	b := startAHoldingServer(t)
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	off.Close() // a laptop that is shut

	machines := []store.AdoptedAgent{
		{AID: "EPhone", URL: a.URL},
		{AID: "ELaptop", URL: b.URL},
		{AID: "EShutLaptop", URL: off.URL},
		{AID: "ENoAddress"},
	}
	holders, couldNotAsk := HoldersFromPairedMachines(machines, "EMyIdentity", HoldingPolicy{}, a.Client(), nil)

	if len(holders) != 2 {
		t.Fatalf("expected the two reachable machines to agree, got %d", len(holders))
	}
	if len(couldNotAsk) != 2 {
		t.Fatalf("expected two machines that could not be asked, got %v", couldNotAsk)
	}
	// And each says WHY, because a holder silently missing from a backup is
	// discovered during a recovery.
	for _, c := range couldNotAsk {
		if c.Why == "" {
			t.Fatalf("machine %s was dropped with no reason given", c.AID)
		}
	}
	// A machine that was shut must not fail the backup — it is one holder
	// fewer, which is what a threshold is built to survive.
	for _, h := range holders {
		if h.Kind != "device" {
			t.Fatalf("a paired machine was recorded as %q", h.Kind)
		}
		if h.PublicKeyB64 == "" {
			t.Fatal("a holder was accepted with no key to seal a share to")
		}
	}
}

// Holders that are all devices earn a warning, and one that includes a person
// does not.
func TestAllDevicesIsSaidOutLoud(t *testing.T) {
	devices := []backup.ShareHolder{{ID: "EPhone", Kind: "device"}, {ID: "ELaptop", Kind: "device"}}
	if AskForMorePeople(devices) == "" {
		t.Fatal("every share on a device the owner carries, and nothing said about it")
	}
	withPerson := append(devices, backup.ShareHolder{ID: "EFriend", Kind: "witness"})
	if AskForMorePeople(withPerson) != "" {
		t.Fatal("naming a person still asked for more people")
	}
	if AskForMorePeople(nil) == "" {
		t.Fatal("nothing protecting the backup at all, and nothing said about it")
	}
}

// startAHoldingServer is a machine that will agree to hold a share.
func startAHoldingServer(t *testing.T) *httptest.Server {
	t.Helper()
	holdings := &Holdings{DataDir: t.TempDir()}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AgreeToHold
		json.NewDecoder(r.Body).Decode(&req)
		agreed, err := holdings.Agree(req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(agreed)
	}))
	t.Cleanup(s.Close)
	return s
}

// A holder does not get to write on the recovery screen.
//
// The reply comes from a machine somebody else runs, and it was being copied
// verbatim into the field whose whole job is to be shown to a person in the
// middle of losing their identity. That is the one screen where a reader is
// most likely to do as they are told.
func TestAMaliciousHolderCannotWriteOnTheScreen(t *testing.T) {
	const lie = "Your recovery has been suspended for fraud. " +
		"Call +1-555-0100 with your recovery words to restore access."

	nasty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"detail":        lie,
			"error":         lie,
			"release_after": lie,
		})
	}))
	defer nasty.Close()

	env := &backup.WhatTheWordsOpen{
		IdentityAID: "EMyIdentity",
		Split: backup.HowTheWayInIsSplit{
			Needed:  1,
			Holders: []backup.ShareHolder{{ID: "ENasty", Kind: "witness", Address: nasty.URL}},
		},
		SealedShares: []backup.SealedShare{{HolderID: "ENasty"}},
	}
	_, state, err := GatherShares(env, nasty.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Holders) != 1 {
		t.Fatalf("expected one holder, got %d", len(state.Holders))
	}
	got := state.Holders[0]
	if strings.Contains(got.Why, "555") || strings.Contains(got.Why, "recovery words") {
		t.Fatalf("a holder wrote its own text onto the recovery screen: %q", got.Why)
	}
	if got.ReleaseAfter != "" {
		t.Fatalf("a holder put %q where a timestamp is shown", got.ReleaseAfter)
	}
}

// An identity comes back THROUGH THE RECOVERY SERVICE, not around it.
//
// Every other end-to-end test here calls backup.OpenArchive directly, and that
// is how a blocking defect stayed invisible: a split archive could not be
// recovered through recovery.Service at all. Verify and Start both refused it,
// so no session could exist for one — which made the cancel window, the duress
// gate, the rotation gate and applyPayload unreachable for exactly the archives
// this design was built for.
//
// An archive that decrypts is not an identity that came back. This asks for the
// identity.
func TestAnIdentityComesBackThroughTheRecoveryService(t *testing.T) {
	const knownAs = "EPairwiseForThisBackup"

	a := startAHolder(t, HoldingPolicy{})
	b := startAHolder(t, HoldingPolicy{})
	holders := []backup.ShareHolder{
		a.agreesToHold(t, knownAs, "EFriendA", HoldingPolicy{}),
		b.agreesToHold(t, knownAs, "EFriendB", HoldingPolicy{}),
	}

	oldDir, oldStore := machineWithAnIdentity(t, "EMyRealIdentity")
	if err := oldStore.SaveContact(contactNamed("EAlice", "Alice")); err != nil {
		t.Fatal(err)
	}
	archive := archiveSplitAcross(t, oldDir, oldStore, holders, 2)
	oldStore.Close()

	env, _, err := backup.OpenBootstrap(archive, backup.OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	shares, state, err := GatherShares(env, a.server.Client())
	if err != nil || !state.Enough() {
		t.Fatalf("could not gather shares: %v %+v", err, state.Holders)
	}
	sharesB64 := map[string]string{}
	for id, raw := range shares {
		sharesB64[id] = backup.EncodeB64(raw)
	}

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer newStore.Close()
	svc := NewService(newDir, newStore, nil)

	// Verifying must not report a split archive as broken.
	verified, err := svc.Verify(VerifyRequest{
		ArchiveB64: backup.EncodeB64(archive),
		Mnemonic:   testPhrase,
		SharesB64:  sharesB64,
	})
	if err != nil {
		t.Fatalf("Verify refused an archive it had every share for: %v", err)
	}
	if verified.IdentityAID != "EMyRealIdentity" {
		t.Fatalf("Verify came back with %q", verified.IdentityAID)
	}

	// And a session can exist for one, which is what everything else hangs off.
	session, err := svc.Start(StartRequest{
		ArchiveB64: backup.EncodeB64(archive),
		Mnemonic:   testPhrase,
		SharesB64:  sharesB64,
	})
	if err != nil {
		t.Fatalf("no session could be started for a split archive: %v", err)
	}
	if session.IdentityAID != "EMyRealIdentity" {
		t.Fatalf("the session is for %q", session.IdentityAID)
	}
}

// Without the shares, the service says so rather than reporting a failure.
func TestTheServiceSaysSharesAreNeededRatherThanFailing(t *testing.T) {
	const knownAs = "EPairwiseForThisBackup"
	a := startAHolder(t, HoldingPolicy{})
	holders := []backup.ShareHolder{a.agreesToHold(t, knownAs, "EFriendA", HoldingPolicy{})}

	oldDir, oldStore := machineWithAnIdentity(t, "EMyRealIdentity")
	archive := archiveSplitAcross(t, oldDir, oldStore, holders, 1)
	oldStore.Close()

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer newStore.Close()

	_, err = NewService(newDir, newStore, nil).Verify(VerifyRequest{
		ArchiveB64: backup.EncodeB64(archive),
		Mnemonic:   testPhrase,
	})
	if err == nil {
		t.Fatal("an archive needing shares was verified without them")
	}
	var needs *backup.ErrNeedsShares
	if !errors.As(err, &needs) {
		t.Fatalf("the service reported needing shares as something else: %v", err)
	}
	// And the sentence does not contradict itself.
	if strings.Contains(err.Error(), "archive open failed") {
		t.Fatalf("the message says the archive failed to open and then that the words "+
			"were right: %q", err)
	}
	if needs.Bootstrap == nil || len(needs.Bootstrap.Split.Holders) != 1 {
		t.Fatal("the refusal does not carry who to ask")
	}
}

// A substituted archive is refused, and the machine's own is not.
//
// This is the whole point of a machine signing its backups. Sealing needs only
// a public key, so anybody can write an archive addressed to an owner — and
// restoring it writes their files, contacts and credentials into the agent.
// The realistic route is whoever controls a destination swapping one archive
// for another.
//
// The owner records the machine's signing key when they pair it, at the one
// moment its hardware vouches for what it hands over. An archive signed with
// anything else is not that machine's.
func TestAnArchiveFromSomebodyElsesMachineIsRefused(t *testing.T) {
	ownerSeed, err := backup.MnemonicToBIP39Seed(testPhrase, "")
	if err != nil {
		t.Fatal(err)
	}
	_, ownerPub, err := backup.DeriveSealKeypair(ownerSeed)
	if err != nil {
		t.Fatal(err)
	}

	// The owner's real machine, and an attacker's, each with their own seed.
	real := aMachineThatWritesBackups(t, ownerPub, 0x11)
	fake := aMachineThatWritesBackups(t, ownerPub, 0x99)

	// The owner paired only one of them.
	paired := []store.AdoptedAgent{{
		AID: "EMyComputer", URL: "https://example",
		BackupSigningKeyB64: backup.EncodeB64(real.pub),
	}}

	// The machine's own archive restores.
	if _, err := RestoreFromArchive(real.archive, OpenRequest{
		Mnemonic: testPhrase, KnownMachines: paired,
	}); err != nil {
		t.Fatalf("the owner's own machine's backup was refused: %v", err)
	}

	// The substitute — correctly sealed to this owner, perfectly openable,
	// written by somebody else — is not.
	_, err = RestoreFromArchive(fake.archive, OpenRequest{
		Mnemonic: testPhrase, KnownMachines: paired,
	})
	if err == nil {
		t.Fatal("an archive written by a machine this owner never paired was restored")
	}
	if !strings.Contains(err.Error(), "no record of which machines") &&
		!strings.Contains(err.Error(), "different machine") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// And knowing about no machines at all is not a reason to accept one.
	if _, err := RestoreFromArchive(real.archive, OpenRequest{
		Mnemonic: testPhrase,
	}); err == nil {
		t.Fatal("an archive was accepted by an owner with no record of any machine")
	}
}

type aWrittenBackup struct {
	pub     []byte
	archive []byte
}

// aMachineThatWritesBackups is a machine with a root seed of its own, writing
// an archive sealed to the owner — which is all a paired computer does.
func aMachineThatWritesBackups(t *testing.T, ownerPub []byte, fill byte) aWrittenBackup {
	t.Helper()
	dir := t.TempDir()
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = fill
	}
	if err := secureenclave.StoreRootSeed(dir, seed); err != nil {
		t.Fatal(err)
	}
	pub, err := secureenclave.BackupSigningPublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	bundle := &backup.PayloadBundle{Sections: map[string][]byte{}}
	bundle.Sections["identity_state"] = []byte(`{"aid":"EMyComputer"}`)
	bundle.Ordered = []backup.PayloadSection{
		{Name: "identity_state", Data: bundle.Sections["identity_state"]},
	}

	c := &backup.Collector{DataDir: dir}
	res, err := c.CreateArchive(
		backup.CollectOptions{Tiers: []string{backup.TierCritical}},
		backup.ExportRequest{
			Tiers: []string{backup.TierCritical}, Bundle: bundle,
			SealToPublicKeys: [][]byte{ownerPub},
		})
	if err != nil {
		t.Fatal(err)
	}
	return aWrittenBackup{pub: pub, archive: res.Bytes}
}

// An archive that says nothing about who wrote it is refused by default.
//
// That default flipped once paired machines began carrying a signing key.
// Before that, refusing would have broken the one backup a paired computer
// could make — a failed recovery is a certainty where a substituted archive is
// a risk — so unattributed archives were tolerated. Both halves now exist, so
// the compromise is over, and an unattributed archive is what a substituted
// one looks like.
//
// It is still openable deliberately, because an archive written before any of
// this is unattributed and is not forged. Deliberately, though, and never by a
// default nobody chose.
func TestAnArchiveThatSaysNothingIsRefusedUnlessSomebodySaysOtherwise(t *testing.T) {
	oldDir, oldStore := machineWithAnIdentity(t, "EMyIdentity")
	archive := archiveWithTheDefaultTiers(t, oldDir, oldStore)
	oldStore.Close()

	// Strip the mark, which is exactly what an archive from before this looks
	// like — and what somebody substituting one would produce.
	arch, err := backup.DecodeArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	arch.Manifest.WrittenBy = ""
	arch.Manifest.AuthTagB64 = ""
	arch.Manifest.WriterKeyB64 = ""
	silent, err := backup.EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RestoreFromArchive(silent, OpenRequest{Mnemonic: testPhrase}); err == nil {
		t.Fatal("an archive that says nothing about who wrote it was restored by default")
	}

	// And openable when somebody says so, having been told what it means.
	if _, err := RestoreFromArchive(silent, OpenRequest{
		Mnemonic: testPhrase, AcceptUnattributed: true,
	}); err != nil {
		t.Fatalf("an old archive could not be opened even deliberately: %v", err)
	}
}

// A machine that wants proof the owner asked gets it, when there is something
// that can sign.
//
// The agent core cannot sign as the root identity — it refuses to, so that a
// core cannot claim an authority it does not have. So this is given a way to
// sign rather than taught to, and what actually signs is whatever holds the
// root key.
func TestAskingAMachineToHoldCarriesTheOwnersSignature(t *testing.T) {
	var sawSig, sawStamp string
	fussy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSig = r.Header.Get("X-IA-Owner-Sig")
		sawStamp = r.Header.Get("X-IA-Owner-Timestamp")
		if sawSig == "" {
			// What a remote paired machine does with an unsigned request.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		holdings := &Holdings{DataDir: t.TempDir()}
		var req AgreeToHold
		json.NewDecoder(r.Body).Decode(&req)
		agreed, err := holdings.Agree(req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(agreed)
	}))
	defer fussy.Close()

	machines := []store.AdoptedAgent{{AID: "ELaptop", URL: fussy.URL}}

	// Nothing to sign with: refused, and it says which kind of refusal it is.
	_, couldNotAsk := HoldersFromPairedMachines(machines, "EMyIdentity", HoldingPolicy{},
		fussy.Client(), nil)
	if len(couldNotAsk) != 1 {
		t.Fatalf("expected the machine to refuse, got %v", couldNotAsk)
	}
	if !strings.Contains(couldNotAsk[0].Why, "was not signed") {
		t.Fatalf("the reason does not say the request was unsigned: %q", couldNotAsk[0].Why)
	}

	// With something that can sign, it agrees.
	signed := func(method, path, timestamp string, body []byte) (string, error) {
		if method != http.MethodPost || path != "/api/recovery/holdings" {
			t.Fatalf("signed the wrong thing: %s %s", method, path)
		}
		if len(body) == 0 {
			t.Fatal("signed a request with no body, so the body is not covered")
		}
		return "a-signature", nil
	}
	holders, couldNotAsk := HoldersFromPairedMachines(machines, "EMyIdentity", HoldingPolicy{},
		fussy.Client(), signed)
	if len(holders) != 1 {
		t.Fatalf("a signed request was still refused: %v", couldNotAsk)
	}
	if sawSig == "" || sawStamp == "" {
		t.Fatal("the request arrived without both the signature and its timestamp")
	}
	if _, err := time.Parse(time.RFC3339, sawStamp); err != nil {
		t.Fatalf("the timestamp is not something a machine can check a window against: %q", sawStamp)
	}
}
