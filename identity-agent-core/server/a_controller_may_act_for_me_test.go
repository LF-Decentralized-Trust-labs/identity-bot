package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func aStore(t *testing.T) *controllerGrants {
	t.Helper()
	return &controllerGrants{dataDir: t.TempDir()}
}

func aGrant(grade ControllerGrade) ControllerGrant {
	return ControllerGrant{
		ControllerAID: "EController123",
		PublicKey:     "DKey456",
		Label:         "the laptop in the study",
		Grade:         grade,
	}
}

// A machine somebody keeps has no expiry, and stands until it is removed.
func TestAMachineSomebodyKeepsLastsUntilRemoved(t *testing.T) {
	c := aStore(t)
	now := time.Now().UTC()

	g, err := c.Grant(aGrant(GradeEnrolled), now)
	if err != nil {
		t.Fatalf("granting: %v", err)
	}
	if !g.ExpiresAt.IsZero() {
		t.Fatalf("a machine somebody keeps should not expire, got %v", g.ExpiresAt)
	}

	// A year on, still theirs.
	if _, ok, _ := c.Live(g.ControllerAID, now.AddDate(1, 0, 0)); !ok {
		t.Fatal("an enrolled controller stopped standing on its own")
	}

	if err := c.Revoke(g.ControllerAID); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, ok, _ := c.Live(g.ControllerAID, now); ok {
		t.Fatal("a revoked controller still stands, which is the whole failure")
	}
}

// A borrowed machine stops on its own. This is the check that stands between a
// computer in a hotel lobby and somebody's identity.
func TestABorrowedMachineStopsOnItsOwn(t *testing.T) {
	c := aStore(t)
	now := time.Now().UTC()

	g, err := c.Grant(aGrant(GradeScoped), now)
	if err != nil {
		t.Fatalf("granting: %v", err)
	}
	if g.ExpiresAt.IsZero() {
		t.Fatal("a borrowed machine was granted forever")
	}

	if _, ok, _ := c.Live(g.ControllerAID, now.Add(time.Hour)); !ok {
		t.Fatal("a borrowed machine stopped standing within its window")
	}
	if _, ok, _ := c.Live(g.ControllerAID, g.ExpiresAt.Add(time.Second)); ok {
		t.Fatal("an expired grant still stands")
	}

	// Expired is reported as absent to a caller asking whether it may act, and
	// still shown to the owner — those are different questions.
	if shown, _ := c.All(); len(shown) != 1 {
		t.Fatal("an expired grant vanished from what the owner is shown")
	}
}

// What a grant must carry to mean anything.
func TestAGrantThatNamesNothingIsRefused(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		g    ControllerGrant
	}{
		{"no identity", ControllerGrant{PublicKey: "D1", Label: "l", Grade: GradeEnrolled}},
		{"no key to check it by", ControllerGrant{ControllerAID: "E1", Label: "l", Grade: GradeEnrolled}},
		{"nothing the owner could recognise", ControllerGrant{ControllerAID: "E1", PublicKey: "D1", Grade: GradeEnrolled}},
		{"neither grade", ControllerGrant{ControllerAID: "E1", PublicKey: "D1", Label: "l", Grade: "admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aStore(t).Grant(tc.g, now); err == nil {
				t.Fatal("accepted a grant that cannot be acted on or revoked")
			}
		})
	}
}

// Granting the same machine twice replaces rather than accumulates, or an owner
// would revoke one grant and find the machine still has another.
func TestGrantingTheSameMachineTwiceReplacesIt(t *testing.T) {
	c := aStore(t)
	now := time.Now().UTC()

	first := aGrant(GradeScoped)
	if _, err := c.Grant(first, now); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	second := aGrant(GradeEnrolled)
	second.Label = "the laptop, kept this time"
	if _, err := c.Grant(second, now); err != nil {
		t.Fatalf("second grant: %v", err)
	}

	all, err := c.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("one machine ended up with %d grants; revoking one would leave the other", len(all))
	}
	if all[0].Grade != GradeEnrolled || all[0].Label != second.Label {
		t.Fatalf("the later grant did not win: %+v", all[0])
	}
	if !all[0].ExpiresAt.IsZero() {
		t.Fatal("regrading to a machine somebody keeps left the borrowed expiry behind")
	}
}

// Grants survive restart — the store is the record, not a cache. Revocation
// likewise: one that took effect only in memory is not a revocation.
func TestGrantsAndRevocationsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	if _, err := (&controllerGrants{dataDir: dir}).Grant(aGrant(GradeEnrolled), now); err != nil {
		t.Fatalf("granting: %v", err)
	}
	if _, ok, _ := (&controllerGrants{dataDir: dir}).Live("EController123", now); !ok {
		t.Fatal("a grant did not survive restart")
	}

	if err := (&controllerGrants{dataDir: dir}).Revoke("EController123"); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, ok, _ := (&controllerGrants{dataDir: dir}).Live("EController123", now); ok {
		t.Fatal("a revocation did not survive restart, so the machine is still in")
	}
}

// Two machines authorised at the same moment both end up authorised.
//
// Each accessor builds its own store value, so a mutex held on that value would
// be a fresh lock every call and would exclude nothing: both calls would read
// the file, each add its own entry to what it read, and the second write would
// drop the first. The owner would have approved two machines and found one.
func TestTwoMachinesAuthorisedAtOnceBothSurvive(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	const machines = 24
	var wg sync.WaitGroup
	for i := 0; i < machines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			g := aGrant(GradeEnrolled)
			g.ControllerAID = fmt.Sprintf("EController%02d", i)
			if _, err := (&controllerGrants{dataDir: dir}).Grant(g, now); err != nil {
				t.Errorf("granting %s: %v", g.ControllerAID, err)
			}
		}(i)
	}
	wg.Wait()

	all, err := (&controllerGrants{dataDir: dir}).All()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(all); got != machines {
		t.Fatalf("%d of %d authorisations survived — the rest were overwritten by "+
			"a grant that arrived at the same time", got, machines)
	}
}

// Revoking something that is not there is what the caller wanted, not an error.
func TestRevokingAMachineThatIsNotThereSucceeds(t *testing.T) {
	if err := aStore(t).Revoke("ENeverGranted"); err != nil {
		t.Fatalf("revoking an absent grant errored: %v", err)
	}
}

// The routes are owner-only, and this is the property everything else rests on:
// anybody who could reach them could authorise their own machine to act as this
// identity's owner.
//
// Driven through the real router rather than by calling classify with a pattern
// written out here. Those two are not the same test: classify keys on the
// pattern chi composes at dispatch, so a hand-typed string that does not match
// it would pass while proving nothing — and it would keep passing after a change
// that genuinely exposed the route.
func TestGrantingAControllerIsRefusedToAnybodyButTheOwner(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")

	for _, c := range []struct{ method, path string }{
		{"POST", "/api/controllers"},
		{"GET", "/api/controllers"},
		{"DELETE", "/api/controllers/EAnyIdentityAtAll"},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, remote(c.method, c.path, `{"controller_aid":"EMine",`+
			`"public_key":"DMine","label":"my laptop","grade":"enrolled"}`))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s from a remote caller: got %d, want 403 — a stranger can "+
				"authorise their own machine to act as this identity's owner",
				c.method, c.path, w.Code)
		}
	}
}

// The routes this test names are the ones actually registered. Without this,
// the test above could be refusing 403s on paths that route nowhere — which is
// what an unmatched path does — and prove nothing about the real ones.
func TestTheControllerRoutesAreTheOnesRegistered(t *testing.T) {
	s := newAuthTestServer(t)
	want := map[string]bool{
		"POST /api/controllers":         false,
		"GET /api/controllers":          false,
		"DELETE /api/controllers/{aid}": false,
	}
	err := chi.Walk(s.buildRouter(""),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if _, ok := want[method+" "+route]; ok {
				want[method+" "+route] = true
				if got := classify(method, route); got != accessOwner {
					t.Errorf("%s %s is %q, not owner-only", method, route, got)
				}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	for k, found := range want {
		if !found {
			t.Errorf("%s is not a route this agent serves, so the test above proves "+
				"nothing about it", k)
		}
	}
}

// A record that cannot be read is never mistaken for one that authorises
// nobody, and above all is not overwritten.
//
// Those two answers are opposites — "this identity has authorised no machines"
// versus "what it authorised could not be read" — and collapsing them destroyed
// the grants: the next write put the empty map back over the file. Three
// authorised machines went, permanently, with nothing said. Reachable without
// anything exotic, since save fsyncs nothing and an unclean shutdown can leave
// this file truncated.
func TestAnUnreadableRecordIsNotAnEmptyOne(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	for _, aid := range []string{"EOne", "ETwo", "EThree"} {
		g := aGrant(GradeEnrolled)
		g.ControllerAID = aid
		if _, err := (&controllerGrants{dataDir: dir}).Grant(g, now); err != nil {
			t.Fatalf("granting %s: %v", aid, err)
		}
	}

	if err := os.WriteFile((&controllerGrants{dataDir: dir}).path(),
		[]byte("{ truncated"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := (&controllerGrants{dataDir: dir}).All(); err == nil {
		t.Fatal("an unreadable record was reported to the owner as an empty one, " +
			"which invites them to grant again over three machines that are still there")
	}
	if _, _, err := (&controllerGrants{dataDir: dir}).Live("EOne", now); err == nil {
		t.Fatal("an unreadable record answered as though the machine was simply not authorised")
	}

	// The writes must refuse rather than replace. This is the part that made the
	// loss permanent.
	g := aGrant(GradeEnrolled)
	g.ControllerAID = "ENew"
	if _, err := (&controllerGrants{dataDir: dir}).Grant(g, now); err == nil {
		t.Fatal("granting wrote over a record it could not read")
	}
	if err := (&controllerGrants{dataDir: dir}).Revoke("EOne"); err == nil {
		t.Fatal("revoking one machine wrote an empty record, revoking every other one too")
	}

	// Repair the file the way restoring a backup would, and everything is still
	// there — which is only true because nothing overwrote it.
	if err := os.WriteFile((&controllerGrants{dataDir: dir}).path(),
		[]byte(`{"EOne":{"controller_aid":"EOne","public_key":"D","label":"l","grade":"enrolled"}}`),
		0o600); err != nil {
		t.Fatal(err)
	}
	if shown, err := (&controllerGrants{dataDir: dir}).All(); err != nil || len(shown) != 1 {
		t.Fatalf("after repair: %d grants, err %v", len(shown), err)
	}
}

// A missing file is genuinely nobody authorised, and stays cheap to ask about.
func TestNoRecordYetIsNotAnError(t *testing.T) {
	all, err := aStore(t).All()
	if err != nil {
		t.Fatalf("an agent that has never authorised a machine reported a fault: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("got %d grants from a fresh agent", len(all))
	}
}

// A borrowed machine cannot be given an expiry that has already passed, or one
// so far away that the grade means nothing.
func TestABorrowedMachineCannotBeGrantedPastOrForever(t *testing.T) {
	now := time.Now().UTC()

	alreadyGone := aGrant(GradeScoped)
	alreadyGone.ExpiresAt = now.Add(-72 * time.Hour)
	if _, err := aStore(t).Grant(alreadyGone, now); err == nil {
		t.Fatal("an authorisation that had already expired was reported as granted, " +
			"so the owner is told a machine was approved that never worked")
	}

	aCentury := aGrant(GradeScoped)
	aCentury.ExpiresAt = now.AddDate(100, 0, 0)
	if _, err := aStore(t).Grant(aCentury, now); err == nil {
		t.Fatal("a borrowed machine was granted a century, which is the permanent " +
			"grade wearing the borrowed one's name")
	}

	// Within the bound is accepted, or the limit would be unusable rather than
	// safe.
	fine := aGrant(GradeScoped)
	fine.ExpiresAt = now.Add(maxScopedGrantLifetime - time.Hour)
	if _, err := aStore(t).Grant(fine, now); err != nil {
		t.Fatalf("a borrowed machine inside the limit was refused: %v", err)
	}
}

// Granting a machine and then listing it describe it the same way.
//
// They did not. The grant route marshalled the struct and the list route built
// its own map, and `omitempty` does not omit a non-pointer struct — so a machine
// the owner KEEPS came back from the grant carrying "expires_at":
// "0001-01-01T00:00:00Z" and from the list carrying no expiry at all. A client
// comparing that date against now reads the machine as long dead, on the very
// response the granting device acts on.
func TestGrantingAndListingDescribeAMachineTheSameWay(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, local("POST", "/api/controllers", `{"controller_aid":"EKept",`+
		`"public_key":"DKept","label":"the laptop in the study","grade":"enrolled"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("granting: %d %s", w.Code, w.Body.String())
	}
	var granted struct {
		Grant map[string]any `json:"grant"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &granted); err != nil {
		t.Fatal(err)
	}
	if _, ok := granted.Grant["expires_at"]; ok {
		t.Fatalf("a machine the owner keeps came back with an expiry: %v",
			granted.Grant["expires_at"])
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, local("GET", "/api/controllers", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("listing: %d %s", w.Code, w.Body.String())
	}
	var listed struct {
		Controllers []map[string]any `json:"controllers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Controllers) != 1 {
		t.Fatalf("listed %d machines after granting one", len(listed.Controllers))
	}

	for _, k := range []string{"controller_aid", "label", "grade", "live", "expires_at"} {
		_, inGrant := granted.Grant[k]
		_, inList := listed.Controllers[0][k]
		if inGrant != inList {
			t.Errorf("%q is on the grant response (%v) and the list response (%v) — "+
				"two views of the same machine disagree about whether it exists",
				k, inGrant, inList)
		}
	}
	if granted.Grant["live"] != true {
		t.Error("a machine just authorised did not come back live")
	}
}
