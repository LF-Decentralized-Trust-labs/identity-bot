package server

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

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

// A vouched statement is judged by its own score, not by the placeholder.
//
// Not a protection yet: while the placeholder stands, a controller that sends
// no statement at all is judged at 80, so it can avoid a low vouched score by
// leaving the statement out. A vouched score means something only once real
// human authentication replaces the placeholder and a missing statement counts
// as nothing measured (ADR-050).
func TestAVouchedStatementIsJudgedByItsOwnScore(t *testing.T) {
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

// The owner-only list is exactly the one ADR-050 records: nothing more is
// closed, and nothing on it was dropped.
func TestTheOwnerOnlyListIsTheOneTheADRRecords(t *testing.T) {
	want := []string{
		"POST /api/controller/sign",
		"POST /api/controller/front-end-for",
		"DELETE /api/controller/front-end-for",
		"POST /api/machines/owner/sign",
		"POST /api/machines/owner-identity",
		"POST /api/pairing/adopt",
		"POST /api/store/event",
		"POST /api/store/identity",
		"POST /api/contacts",
		"PUT /api/contacts/{aid}",
		"POST /api/contacts/resolve",
		"POST /api/scan/execute",
		"POST /api/ask/create",
		"DELETE /api/contacts/{aid}",
		"POST /api/controllers",
		"DELETE /api/controllers/{aid}",
		"POST /api/rotation",
		"POST /api/recovery/root-aid-rotation",
		"POST /api/keystore/root-seed",
		"POST /api/reset",
		"POST /api/inception",
		"POST /api/hybrid-inception",
		"POST /api/messaging-keys/prepare",
		"POST /api/owners/ceremony",
		"DELETE /api/owners/ceremony",
		"POST /api/interact",
		"POST /api/session/grant",
		"POST /api/recovery/verify",
		"POST /api/recovery/start",
		"POST /api/recovery/sessions/{id}/activate",
		"POST /api/recovery/sessions/{id}/rotation",
		"POST /api/recovery/sessions/{id}/cancel",
		"PUT /api/recovery/who-holds-this",
		"PUT /api/recovery/duress-policy",
		"POST /api/recovery/holdings",
		"POST /api/recovery/holdings/approve",
		"POST /api/recovery/holdings/stop",
		"POST /api/signer/invites",
		"POST /api/signer/invites/{token}/redeem",
		"POST /api/recovery/retrieve",
		"POST /api/backup/export",
		"POST /api/backup/pull/{destID}",
		"POST /api/sign",
		"POST /api/events/signature",
		// Key events, which ADR-050 lists under who the owner is, prepared and
		// committed signed (ADR-061).
		"POST /api/events/prepare",
		"POST /api/events/commit",
		"POST /api/signing-requests/{id}/fulfil",
		"POST /api/signing-requests/{id}/refuse",
		"POST /api/signing-requests/sign-for-another",
		"POST /api/signing-requests/adopt",
		"POST /api/didcomm/peers",
		"POST /api/providers",
		"POST /api/capability-registry/packs",
		"POST /api/capability-registry/{id}/enabled",
		"DELETE /api/capability-registry/{id}",
		"POST /api/sealed/send",
		// ADR-050 also records POST /api/sandbox/podman/setup. It is the
		// sandboxed-apps add-on's route, so that add-on closes it with its
		// own rule (Addon.ControllerOwnerOnly), tested with the add-on.
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
		t.Fatalf("the owner-only list is not the one ADR-050 records.\nwant:\n%s\nhave:\n%s",
			strings.Join(want, "\n"), strings.Join(have, "\n"))
	}
}

// A vouched statement's level is derived from its score, so the two cannot
// disagree: a statement naming the strongest level with a score of 50 is
// recorded at the level 50 falls in.
func TestAVouchedLevelIsDerivedFromItsScore(t *testing.T) {
	s := newAuthTestServer(t)
	aid, _ := anAuthorisedMachine(t, s, GradeEnrolled)
	at := time.Now().UTC()
	req := remote("GET", "/api/profile", "")
	req.Header.Set(headerControllerAuthLevel, string(authprovider.LevelHigh))
	req.Header.Set(headerControllerAuthAt, at.Format(time.RFC3339))
	req.Header.Set(headerControllerAuthScore, "50")
	req.Header.Set(headerAuthLevelVouchedBy, theRootDeviceVouches(t, aid, authprovider.LevelHigh, at, 50))

	got := s.theAuthenticationSomebodyVouchedFor(req, aid, at)
	if !got.Measured || got.Score != 50 {
		t.Fatalf("the vouched statement was not read: %+v", got)
	}
	if got.Level != authprovider.LevelForScore(50) {
		t.Fatalf("the statement's level %q disagrees with its score of 50", got.Level)
	}
}
