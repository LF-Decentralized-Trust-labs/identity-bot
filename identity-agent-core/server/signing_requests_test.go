package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

func signingServer(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	return &CoreServer{DataDir: dir, DataStore: ds}
}

// ownerRequest builds a request this agent will treat as its owner's.
//
// Ownership is loopback-without-forwarding-headers, so the test has to say
// where it is coming from. httptest defaults to a non-loopback address, which
// would make every owner-only test pass for the wrong reason.
func ownerRequest(method, path string, body io.Reader, _ *CoreServer) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "127.0.0.1:54321"
	return r
}

func withID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// What is queued must be exactly what gets signed. Storing the payload rather
// than reconstructing it later is what stops what was shown and what was signed
// from drifting apart.
func TestAQueuedRequestKeepsThePayloadItWillSign(t *testing.T) {
	s := signingServer(t)
	payload := []byte(`{"r":"/loc/scheme","a":{"url":"https://relay-b.test"}}`)

	id, err := s.EnqueueSigningRequest("ERoot", "endpoint-location",
		"Publish your new address", "Your phone holds the key, so it has to sign this",
		payload, false)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	req, err := s.DataStore.GetSigningRequest(id)
	if err != nil || req == nil {
		t.Fatalf("read back: %v", err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(req.PayloadB64)
	if !bytes.Equal(decoded, payload) {
		t.Errorf("the stored payload is not what was queued")
	}
	if req.Status != SigningStatusPending {
		t.Errorf("a new request should be pending, got %q", req.Status)
	}
}

// A request with nothing to sign is not a request.
func TestAnEmptyRequestIsRefused(t *testing.T) {
	s := signingServer(t)
	if _, err := s.EnqueueSigningRequest("ERoot", "kind", "summary", "", nil, false); err == nil {
		t.Error("a request with no payload was accepted")
	}
	if _, err := s.EnqueueSigningRequest("", "kind", "summary", "", []byte("x"), false); err == nil {
		t.Error("a request with no AID was accepted")
	}
}

// A blank prompt on somebody's phone is worse than an awkward default.
func TestARequestAlwaysHasSomethingToShow(t *testing.T) {
	s := signingServer(t)
	id, err := s.EnqueueSigningRequest("ERoot", "endpoint-location", "", "", []byte("x"), false)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := s.DataStore.GetSigningRequest(id)
	if req.Summary == "" {
		t.Error("a request was queued with nothing for a person to read")
	}
}

// The signature is recorded and the request closed.
func TestFulfillingRecordsTheSignature(t *testing.T) {
	s := signingServer(t)
	id, _ := s.EnqueueSigningRequest("ERoot", "endpoint-location", "Publish", "", []byte("x"), false)

	body, _ := json.Marshal(map[string]string{"signature": "0Bsignature"})
	r := withID(ownerRequest(http.MethodPost, "/api/signing-requests/"+id+"/fulfil",
		bytes.NewReader(body), s), id)
	w := httptest.NewRecorder()
	s.handleFulfilSigningRequest(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("fulfil failed: %d %s", w.Code, w.Body.String())
	}
	req, _ := s.DataStore.GetSigningRequest(id)
	if req.Status != SigningStatusSigned || req.Signature != "0Bsignature" {
		t.Errorf("signature not recorded: status=%q sig=%q", req.Status, req.Signature)
	}
}

// A request already answered must not be answerable again, or a stale client
// could silently replace a refusal with a signature.
func TestAResolvedRequestCannotBeAnsweredTwice(t *testing.T) {
	s := signingServer(t)
	id, _ := s.EnqueueSigningRequest("ERoot", "endpoint-location", "Publish", "", []byte("x"), false)

	// Refuse it first.
	r := withID(ownerRequest(http.MethodPost, "/api/signing-requests/"+id+"/refuse", nil, s), id)
	w := httptest.NewRecorder()
	s.handleRefuseSigningRequest(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("refuse failed: %d %s", w.Code, w.Body.String())
	}

	// Now try to sign it anyway.
	body, _ := json.Marshal(map[string]string{"signature": "0Bsignature"})
	r = withID(ownerRequest(http.MethodPost, "/api/signing-requests/"+id+"/fulfil",
		bytes.NewReader(body), s), id)
	w = httptest.NewRecorder()
	s.handleFulfilSigningRequest(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("a refusal was overwritten by a signature: %d", w.Code)
	}
	req, _ := s.DataStore.GetSigningRequest(id)
	if req.Status != SigningStatusRefused {
		t.Errorf("status is %q, expected the refusal to stand", req.Status)
	}
}

// A refusal is recorded rather than deleted: "you said no" is a different state
// from "you were never asked".
func TestARefusalIsRecordedNotErased(t *testing.T) {
	s := signingServer(t)
	id, _ := s.EnqueueSigningRequest("ERoot", "endpoint-location", "Publish", "", []byte("x"), false)

	r := withID(ownerRequest(http.MethodPost, "/api/signing-requests/"+id+"/refuse", nil, s), id)
	s.handleRefuseSigningRequest(httptest.NewRecorder(), r)

	req, err := s.DataStore.GetSigningRequest(id)
	if err != nil || req == nil {
		t.Fatal("the refused request was erased")
	}
	if req.Status != SigningStatusRefused || req.ResolvedAt == "" {
		t.Errorf("refusal not recorded properly: %+v", req)
	}
}

// A stale request must not be shown as actionable just because no sweep has run.
func TestAnExpiredRequestIsNotListed(t *testing.T) {
	s := signingServer(t)

	// Written directly with a past deadline, because a request's expiry is
	// fixed at creation and deliberately cannot be moved by a later save.
	if err := s.DataStore.SaveSigningRequest(store.SigningRequest{
		ID: "already-lapsed", AID: "ERoot", Kind: "endpoint-location",
		Summary: "Publish", PayloadB64: "eA==", Status: SigningStatusPending,
		CreatedAt: time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		ExpiresAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.handleListSigningRequests(w, ownerRequest(http.MethodGet, "/api/signing-requests", nil, s))
	if w.Code != http.StatusOK {
		t.Fatalf("list failed: %d", w.Code)
	}
	var out struct {
		Count int `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Count != 0 {
		t.Errorf("an expired request was listed as actionable")
	}

	// And it is closed rather than left pending, so it stops being asked about.
	lapsed, _ := s.DataStore.GetSigningRequest("already-lapsed")
	if lapsed == nil || lapsed.Status != SigningStatusExpired {
		t.Errorf("the lapsed request was not marked expired: %+v", lapsed)
	}
}

// Only the owner can sign for this agent, or see what it is about to assert.
func TestSigningRequestsAreOwnerOnly(t *testing.T) {
	s := signingServer(t)
	id, _ := s.EnqueueSigningRequest("ERoot", "endpoint-location", "Publish", "", []byte("x"), false)

	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"list":   s.handleListSigningRequests,
		"fulfil": s.handleFulfilSigningRequest,
		"refuse": s.handleRefuseSigningRequest,
	} {
		r := withID(httptest.NewRequest(http.MethodPost, "/api/signing-requests", nil), id)
		w := httptest.NewRecorder()
		call(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s was reachable without owner credentials: %d", name, w.Code)
		}
	}
}
