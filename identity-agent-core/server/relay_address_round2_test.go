package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/enrolsecret"
	"identity-agent-core/store"
)

func labelOf(addr string) string { return addr[strings.LastIndex(addr, "/")+1:] }

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// (a) A relationship the relay will not make an address for is refused with an
// error that says to try again. It is never made at the shared address.
func TestARelationshipIsRefusedWhenTheRelayWillNotMakeItAnAddress(t *testing.T) {
	s, rl, shared := privateRelayWithEngine(t)
	ownerWithRootAndProfile(t, s)
	rl.Down(true)

	if _, _, _, err := s.mintPairwise("refused"); !errors.Is(err, errRelayAddressUnavailable) {
		t.Fatalf("a relationship was made with no address of its own: %v", err)
	}
	w := ownerGet(s, "/api/oobi")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("the refusal is not retryable: %d %q %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
	if strings.Contains(w.Body.String(), shared) || strings.Contains(w.Body.String(), "/public/oobi/") {
		t.Errorf("the refusal handed out an address: %s", w.Body)
	}

	rl.Down(false)
	waitUntil(t, "the relay to answer again", func() bool {
		_, _, _, err := s.mintPairwise("again")
		return err == nil
	})
}

// (b) Everything written for a counterparty names the address made for that
// relationship, not the shared one.
func TestEveryOfferNamesItsOwnRelationshipsAddress(t *testing.T) {
	s, _, shared := privateRelayWithEngine(t)
	ownerWithRootAndProfile(t, s)
	h, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.assetHandler = h
	if err := h.Store.UpsertAsset(asset.Asset{ID: "portal-1", AssetType: "app",
		PairwiseAID: "EPortalForRelationshipTests00000000000000000", DelegatorAID: rootAIDForOobiTests}); err != nil {
		t.Fatal(err)
	}
	s.router = s.buildRouter()
	// The fixture's enrolment sits at index 4 of the pool contacts are made from;
	// step past it so no relationship here is made as that identifier.
	for i := 0; i < 6; i++ {
		if _, err := s.DataStore.AllocateNextRelationshipIndex("contacts"); err != nil {
			t.Fatal(err)
		}
	}

	urlOf := func(path, body, field string) string {
		w := ownerDo(s, http.MethodPost, path, body)
		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			t.Fatalf("POST %s: %d %s", path, w.Code, w.Body)
		}
		var got map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		u, _ := got[field].(string)
		return u
	}
	oobi := func() string {
		w := ownerGet(s, "/api/oobi")
		var got map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		u, _ := got["oobi_url"].(string)
		return u
	}
	links := map[string]string{
		"/api/oobi":              oobi(),
		"/api/ask/create":        urlOf("/api/ask/create", `{"t":2}`, "url"),
		"/api/signer/invites":    urlOf("/api/signer/invites", `{}`, "url"),
		"/api/employees/invites": urlOf("/api/employees/invites", `{"role":"x","asset_id":"portal-1"}`, "url"),
	}
	seen := map[string]string{}
	for route, link := range links {
		if link == "" || strings.HasPrefix(link, shared+"/") || link == shared {
			t.Errorf("%s handed out the shared address: %q (shared %s)", route, link, shared)
			continue
		}
		base := link[:strings.Index(link[len("https://"):], "/")+len("https://")+1]
		_ = base
		l := strings.SplitN(strings.TrimPrefix(link, "https://"), "/", 3)
		if len(l) < 2 {
			t.Errorf("%s: %q is not at a relay address", route, link)
			continue
		}
		if other, dup := seen[l[1]]; dup {
			t.Errorf("%s and %s were given the same address %s", route, other, l[1])
		}
		seen[l[1]] = route
	}
}

// (c) The address is given back on every way a relationship ends, not only when
// a contact is deleted.
func TestEveryWayARelationshipEndsGivesItsAddressBack(t *testing.T) {
	s, rl, _ := privateRelayWithEngine(t)
	ownerWithRootAndProfile(t, s)
	h, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.assetHandler = h
	s.router = s.buildRouter()

	held := func(aid string) (string, bool) {
		a := s.currentRelay().AddressFor(aid)
		if a == nil {
			return "", false
		}
		return a.Label, true
	}
	gone := func(what, label string) {
		t.Helper()
		waitUntil(t, what+": the relay to let the address go", func() bool { return !rl.Holds(label) })
	}

	// An invitation revoked.
	w := ownerDo(s, http.MethodPost, "/api/signer/invites", `{}`)
	var inv struct {
		Invite asset.EmployeeInvite `json:"invite"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &inv)
	if w.Code != http.StatusOK || inv.Invite.Token == "" {
		t.Fatalf("no invitation: %d %s", w.Code, w.Body)
	}
	id := enrolsecret.Digest(inv.Invite.Token)
	aids := s.endsOrLoad().Handles["invite:"+id]
	if len(aids) != 1 {
		t.Fatalf("the relationship made for the invitation was not recorded: %v", s.endsOrLoad().Handles)
	}
	label, ok := held(aids[0])
	if !ok || !rl.Holds(label) {
		t.Fatal("the invitation has no address at the relay")
	}
	if rec := ownerDo(s, http.MethodDelete, "/api/employees/invites/"+id, ""); rec.Code != http.StatusOK {
		t.Fatalf("revoking the invitation: %d %s", rec.Code, rec.Body)
	}
	gone("a revoked invitation", label)

	// A member revoked.
	w = ownerDo(s, http.MethodPost, "/api/signer/invites", `{}`)
	_ = json.Unmarshal(w.Body.Bytes(), &inv)
	id = enrolsecret.Digest(inv.Invite.Token)
	aids = s.endsOrLoad().Handles["invite:"+id]
	label, _ = held(aids[0])
	if err := h.Store.UpsertEmployee(asset.Employee{PairwiseAID: "EMemberToRevoke0000000000000000000000000", Role: "x",
		Status: "active", InviteToken: id}); err != nil {
		t.Fatal(err)
	}
	if rec := ownerDo(s, http.MethodPost, "/api/employees/EMemberToRevoke0000000000000000000000000/revoke", ""); rec.Code != http.StatusOK {
		t.Fatalf("revoking the member: %d %s", rec.Code, rec.Body)
	}
	gone("a revoked member", label)

	// A machine forgotten (unpaired from this side).
	aid, _, _, _, err := s.mintPairwiseIn("machines", "machine-to-forget")
	if err != nil {
		t.Fatal(err)
	}
	label, _ = held(aid)
	if err := s.DataStore.SaveAdoptedAgent(store.AdoptedAgent{AID: "EBoxToForget00000000000000000000000000000", OwnerAID: aid,
		URL: "https://box.example.test", Kind: "box"}); err != nil {
		t.Fatal(err)
	}
	if rec := ownerDo(s, http.MethodDelete, "/api/agents/EBoxToForget00000000000000000000000000000", ""); rec.Code != http.StatusOK {
		t.Logf("forget route answered %d %s", rec.Code, rec.Body)
	}
	gone("a forgotten machine", label)
}

// (c) A relationship that cannot be recorded after its address is made gives the
// address back.
type forgetsNothing struct{ store.Store }

func (forgetsNothing) RememberMachineOwnerIdentity(string, int) error {
	return errors.New("the store is read-only")
}

func TestAnAddressIsGivenBackWhenSavingTheRelationshipFails(t *testing.T) {
	s, rl, _ := privateRelayWithEngine(t)
	s.DataStore = forgetsNothing{s.DataStore}

	before := len(s.currentRelay().RelationshipAddresses())
	if _, _, err := s.mintAnIdentityToClaimAMachineWith(); err == nil {
		t.Fatal("the machine's identity was recorded by a store that refuses")
	}
	waitUntil(t, "the unrecorded relationship's address to go back", func() bool {
		return len(s.currentRelay().RelationshipAddresses()) == before
	})
	// And the relay itself holds only the primary address.
	waitUntil(t, "the relay to forget it", func() bool {
		n := 0
		for _, a := range s.currentRelay().Allocations() {
			if rl.Holds(a.Label) {
				n++
			}
		}
		return n == 1
	})
}

// (e) Where a relationship is reached is published when its address is made, is
// not published again when nothing changed, and is withdrawn when it is gone.
func TestWhereARelationshipIsReachedIsRepublished(t *testing.T) {
	s, _, _ := privateRelayWithEngine(t)
	var mu sync.Mutex
	published := map[string][]string{}
	s.publishEndpoint = func(_ context.Context, aid, address string) error {
		mu.Lock()
		defer mu.Unlock()
		published[aid] = append(published[aid], address)
		return nil
	}
	last := func(aid string) []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), published[aid]...)
	}

	aid, oobi, _, _, err := s.mintPairwiseIn("contacts", "republished")
	if err != nil {
		t.Fatal(err)
	}
	addr := addressOf(t, oobi, aid)
	waitUntil(t, "the address to be published", func() bool { return len(last(aid)) == 1 })
	if got := last(aid)[0]; got != addr {
		t.Errorf("published %q, the relationship is at %q", got, addr)
	}

	s.republishRelationshipAddresses(s.currentRelay())
	time.Sleep(100 * time.Millisecond)
	if n := len(last(aid)); n != 1 {
		t.Errorf("an unchanged address was published again (%d records)", n)
	}

	if err := s.currentRelay().ReleaseFor(s.backgroundContext(), aid); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the withdrawal", func() bool { p := last(aid); return len(p) == 2 && p[1] == "" })
}
