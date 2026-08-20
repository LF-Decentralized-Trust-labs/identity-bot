package recovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/backup"
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

// A machine agreeing twice would invalidate every share already sealed to it.
func TestAgreeingTwiceIsRefused(t *testing.T) {
	h := startAHolder(t, HoldingPolicy{})
	if _, err := h.holdings.Agree(AgreeToHold{IdentityAID: "EX", HolderID: "EMe"}); err != nil {
		t.Fatal(err)
	}
	_, err := h.holdings.Agree(AgreeToHold{IdentityAID: "EX", HolderID: "EMe"})
	if err == nil {
		t.Fatal("agreeing twice minted a second key and orphaned every existing share")
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
	holders, couldNotAsk := HoldersFromPairedMachines(machines, "EMyIdentity", HoldingPolicy{}, a.Client())

	if len(holders) != 2 {
		t.Fatalf("expected the two reachable machines to agree, got %d", len(holders))
	}
	if len(couldNotAsk) != 2 {
		t.Fatalf("expected two machines that could not be asked, got %v", couldNotAsk)
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
