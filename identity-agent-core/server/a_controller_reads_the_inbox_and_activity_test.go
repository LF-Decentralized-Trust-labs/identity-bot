package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// asTheController is a request from far away that an authorised machine signed:
// the shape the controller gate hands on after admitting it.
func asTheController(method, path string) *http.Request {
	r := remote(method, path, "")
	return r.WithContext(context.WithValue(r.Context(), controllerContextKey{},
		ControllerGrant{ControllerAID: "BAUTHORISEDLAPTOP"}))
}

// The router admits a controller to both reads. The handlers used to refuse it
// again with an owner-only check of their own, so the front end could reach the
// route and still never see the inbox or the activity log.
func TestAControllerReadsTheInboxAndTheActivityLog(t *testing.T) {
	s := agentWithNoIdentity(t)

	rec := httptest.NewRecorder()
	s.handleGetDIDCommInbox(rec, asTheController("GET", "/api/didcomm/inbox"))
	if rec.Code == http.StatusForbidden {
		t.Fatalf("an authorised controller was refused the inbox: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	if !s.requireOwner(rec, asTheController("GET", "/api/activity/invocations")) {
		t.Fatalf("an authorised controller was refused the activity log: %s", rec.Body.String())
	}
}

// Neither door opens for a caller that is not the owner and not a controller,
// and an AI agent's bearer token still does not read the activity log.
func TestOnlyTheOwnerOrAControllerReadsThem(t *testing.T) {
	s := agentWithNoIdentity(t)

	rec := httptest.NewRecorder()
	s.handleGetDIDCommInbox(rec, remote("GET", "/api/didcomm/inbox", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a stranger read the inbox (%d)", rec.Code)
	}

	r := local("GET", "/api/activity/invocations", "")
	r.Header.Set("Authorization", "Bearer iamcp_anagentstoken")
	if s.requireOwner(httptest.NewRecorder(), r) {
		t.Fatal("an AI agent's token read the activity log")
	}
}
