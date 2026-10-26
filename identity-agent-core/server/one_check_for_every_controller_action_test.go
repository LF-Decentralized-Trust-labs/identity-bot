package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/buildmode"

	"github.com/go-chi/chi/v5"
)

// A controller with nothing vouched for it creates an AI agent in a production
// build. Before the one check this was refused: creating an AI agent was raised
// to a named level nothing could produce, and only a development build stood in
// for the missing measurement.
func TestAControllerCreatesAnAIAgentWithNothingVouchedInAProductionBuild(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("this proves the production build; run without the development flag")
	}
	w := newTalkWorld(t)
	body := `{"name":"Clerk","capabilities":["` + capabilityMessageAgent + `"]}`
	req := asThatMachineTo(t, w.s.thisIdentityAgentsIdentifier(), w.ctlAID, "POST", "/api/mcp/agents",
		body, w.ctlSeed, "", time.Time{})
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("a controller with the placeholder score could not create an AI agent: %d %s",
			rec.Code, rec.Body.String())
	}
}

// The owner-only list is refused at any score, including the strongest a root
// device could vouch for.
func TestOwnerOnlyActionsAreRefusedAtAnyScore(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	for i, route := range []struct{ method, path string }{
		{"POST", "/api/rotation"},
		{"DELETE", "/api/controllers/BSomeOtherMachine"},
	} {
		for j, vouched := range []int{0, 80, 100} {
			level := authprovider.Level("")
			if vouched > 0 {
				level = authprovider.LevelHigh
			}
			// Each request its own moment, so none is refused as a reused signature.
			at := time.Now().Add(-time.Duration(i*3+j) * time.Second)
			req := asThatMachineScored(t, "", aid, route.method, route.path, `{}`, seed, level, at, vouched)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s %s was allowed to a controller vouched at %d: %d %s",
					route.method, route.path, vouched, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "owner's keys") {
				t.Errorf("%s %s was refused without saying it is done with the owner's keys: %s",
					route.method, route.path, w.Body.String())
			}
		}
	}
}

// An action whose minimum is set to 90 is refused at the placeholder 80, and
// opened by a fresh vouched statement of 95. A stale statement is not used,
// so it falls back to the placeholder and is refused again.
func TestAControllerActionNeedingNinetyIsRefusedAtThePlaceholder(t *testing.T) {
	const route = "GET /api/profile"
	controllerMinimumScore[route] = 90
	t.Cleanup(func() { delete(controllerMinimumScore, route) })

	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("an action needing 90 was allowed at the placeholder 80: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "90") {
		t.Errorf("the refusal does not say what score was needed: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachineScored(t, "", aid, "GET", "/api/profile", "", seed,
		authprovider.LevelHigh, time.Now().Add(-time.Second), 95))
	if w.Code == http.StatusForbidden {
		t.Fatalf("a fresh vouched 95 was refused an action needing 90: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachineScored(t, "", aid, "GET", "/api/profile", "", seed,
		authprovider.LevelHigh, time.Now().Add(-2*controllerAuthenticationFreshness), 95))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a vouched score from %s ago opened an action needing 90: %d",
			2*controllerAuthenticationFreshness, w.Code)
	}
}

// A vouched score below 80 is used as it is: somebody checked and fell short,
// which is not the same as nobody having checked.
func TestAVouchedScoreBelowEightyIsRefused(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachineScored(t, "", aid, "GET", "/api/profile", "", seed,
		authprovider.LevelHigh, time.Now(), 50))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a vouched score of 50 cleared the default minimum of 80: %d", w.Code)
	}
}

// The decision compares scores, never named levels: a statement naming the
// strongest level with a low score is refused, and the badge shown for the
// placeholder is green.
func TestTheDecisionReadsTheScoreNotTheLevel(t *testing.T) {
	low := authprovider.Result{Level: authprovider.LevelHigh, Score: 10, Measured: true, At: time.Now().UTC()}
	if ok, _ := mayThisControllerDoThis("GET", "/api/profile", "EMachine", low); ok {
		t.Fatal("the strongest named level with a score of 10 was allowed")
	}
	ph := authprovider.UntilHumanAuthenticationIsBuilt(time.Now())
	if authprovider.BadgeForScore(ph.Score) != "green" {
		t.Fatal("the placeholder score is not shown green")
	}
}

// The owner-only list is exactly the ruling: nothing more is closed, and
// nothing on it was dropped.
func TestTheOwnerOnlyListIsTheRuling(t *testing.T) {
	want := []string{
		// closed before the ruling
		"POST /api/controller/sign",
		"POST /api/controller/front-end-for",
		"DELETE /api/controller/front-end-for",
		"POST /api/machines/owner/sign",
		"POST /api/machines/owner-identity",
		"POST /api/store/event",
		"POST /api/store/identity",
		"POST /api/contacts",
		"PUT /api/contacts/{aid}",
		"POST /api/contacts/resolve",
		"POST /api/scan/execute",
		"POST /api/ask/create",
		"DELETE /api/contacts/{aid}",
		"POST /api/controllers",
		// added by the ruling
		"POST /api/rotation",
		"POST /api/recovery/root-aid-rotation",
		"POST /api/keystore/root-seed",
		"POST /api/reset",
		"POST /api/inception",
		"POST /api/recovery/start",
		"POST /api/recovery/sessions/{id}/activate",
		"POST /api/recovery/sessions/{id}/rotation",
		"POST /api/recovery/sessions/{id}/cancel",
		"PUT /api/recovery/who-holds-this",
		"PUT /api/recovery/duress-policy",
		"POST /api/signer/invites",
		"POST /api/signer/invites/{token}/redeem",
		"DELETE /api/controllers/{aid}",
		"POST /api/recovery/retrieve",
		"POST /api/backup/export",
		"POST /api/backup/pull/{destID}",
		"POST /api/sign",
		"POST /api/events/signature",
		"POST /api/signing-requests/{id}/fulfil",
	}
	have := make([]string, 0, len(controllerOwnerOnly))
	for route, why := range controllerOwnerOnly {
		have = append(have, route)
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s is owner-only without saying why", route)
		}
	}
	sort.Strings(want)
	sort.Strings(have)
	if strings.Join(want, "\n") != strings.Join(have, "\n") {
		t.Fatalf("the owner-only list is not the ruling.\nwant:\n%s\nhave:\n%s",
			strings.Join(want, "\n"), strings.Join(have, "\n"))
	}
}

// Every owner-only entry and every per-action minimum names a route this
// Identity Agent actually serves. The maps are keyed by hand-typed strings, and
// a key that matches no route guards nothing while looking exactly like
// protection.
func TestEveryControllerRuleNamesARouteThisAgentServes(t *testing.T) {
	s := newAuthTestServer(t)
	// The employee and signer routes are mounted only with an asset handler.
	ah, err := asset.NewHandler(s.DataDir, nil)
	if err != nil {
		t.Fatalf("asset handler: %v", err)
	}
	s.assetHandler = ah

	served := map[string]bool{}
	if werr := chi.Walk(s.buildRouter(""),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			served[method+" "+route] = true
			return nil
		}); werr != nil {
		t.Fatalf("walking the router: %v", werr)
	}
	for route := range controllerOwnerOnly {
		if !served[route] {
			t.Errorf("%s is owner-only but this Identity Agent serves no such route", route)
		}
	}
	for route := range controllerMinimumScore {
		if !served[route] {
			t.Errorf("%s has a minimum score but this Identity Agent serves no such route", route)
		}
	}
}

// What a controller makes is recorded against it, because it keeps working
// after the controller's grant is revoked or expires: an AI agent and its
// token, a token minted on its own, and a member's approval.
func TestWhatAControllerMakesIsRecordedAgainstIt(t *testing.T) {
	w := newTalkWorld(t)
	me := w.s.thisIdentityAgentsIdentifier()
	send := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := asThatMachineTo(t, me, w.ctlAID, method, path, body, w.ctlSeed, "", time.Time{})
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, req)
		return rec
	}

	rec := send("POST", "/api/mcp/agents", `{"name":"Made by a machine","capabilities":["`+capabilityMessageAgent+`"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provisioning: %d %s", rec.Code, rec.Body.String())
	}
	var made struct {
		AssetID string `json:"asset_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if a, ok := w.s.assetHandler.Store.GetAsset(made.AssetID); !ok || a.MadeByController != w.ctlAID {
		t.Fatalf("the AI agent does not record the machine that made it: %+v", a)
	}

	rec = send("POST", "/api/mcp/tokens", `{"name":"machine-token","scopes":["`+capabilityMessageAgent+`"]}`)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("minting: %d %s", rec.Code, rec.Body.String())
	}
	byName := map[string]string{}
	for _, tok := range w.s.loadMCPTokens() {
		byName[tok.Name] = tok.MadeByController
	}
	if byName["machine-token"] != w.ctlAID || byName["Made by a machine"] != w.ctlAID {
		t.Fatalf("a token does not record the machine that minted it: %v", byName)
	}

	if err := w.s.assetHandler.Store.UpsertEmployee(asset.Employee{
		PairwiseAID: "EMember", Name: "Sam", Role: "Staff", Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}
	rec = send("POST", "/api/employees/EMember/approve", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", rec.Code, rec.Body.String())
	}
	if e, _ := w.s.assetHandler.Store.GetEmployee("EMember"); e.ApprovedByController != w.ctlAID {
		t.Fatalf("a member's approval does not record the machine that gave it: %+v", e)
	}
}
