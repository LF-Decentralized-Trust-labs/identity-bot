package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

// A witness holding endpoint records needs a real store — the whole point is
// that it can answer later.
func witnessWithStore(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	return &CoreServer{DataDir: dir, DataStore: ds}
}

func postEndpointRecord(t *testing.T, s *CoreServer, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/witness/endpoint", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	s.handleWitnessEndpointRecord(w, r)
	return w
}

func locSchemeRecord(said, url string) map[string]any {
	return map[string]any{
		"v": "KERI10JSON0000e4_", "t": "rpy", "d": said,
		"dt": "2026-07-29T23:17:28.768864+00:00", "r": "/loc/scheme",
		"a": map[string]any{"eid": "EController", "scheme": "https", "url": url},
	}
}

// One identity must not be able to publish endpoints under another's name. The
// record carries its own cid; trusting the envelope over it would let anyone
// redirect anyone.
func TestEndpointRecordRefusesAMismatchedController(t *testing.T) {
	s := witnessWithStore(t)
	rec := map[string]any{
		"v": "KERI10JSON0000d9_", "t": "rpy", "d": "EEndRoleSaid",
		"r": "/end/role/add",
		"a": map[string]any{"cid": "ESomebodyElse", "role": "mailbox", "eid": "EMailbox"},
	}
	w := postEndpointRecord(t, s, map[string]any{"aid": "EController", "record": rec})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a record naming a different controller was accepted: status %d", w.Code)
	}
}

// A key event routed here would skip the KEL's sequence and duplicity checks
// entirely, so the route is checked rather than assumed.
func TestEndpointRecordRefusesAKeyEvent(t *testing.T) {
	s := witnessWithStore(t)
	icp := map[string]any{
		"v": "KERI10JSON000159_", "t": "icp", "d": "EInceptionSaid",
		"r": "/icp", "s": "0",
	}
	w := postEndpointRecord(t, s, map[string]any{"aid": "EController", "record": icp})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a key event was accepted as an endpoint record: status %d", w.Code)
	}
}

// Storing is keyed by SAID, so a witness that receives the same record twice
// holds it once — replay must not multiply.
func TestEndpointRecordIsIdempotent(t *testing.T) {
	s := witnessWithStore(t)
	rec := locSchemeRecord("ELocSaidOne", "https://k7f2pq9r.relay-a.test")

	for i := 0; i < 3; i++ {
		if w := postEndpointRecord(t, s, map[string]any{"aid": "EController", "record": rec}); w.Code != http.StatusOK {
			t.Fatalf("store attempt %d failed: status %d body %s", i+1, w.Code, w.Body.String())
		}
	}

	records, err := s.DataStore.GetEndpointRecords("EController")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("the same record stored %d times, want 1", len(records))
	}
}

// Superseding is by publishing a NEW record, not by mutating the old one — the
// earlier statement stays so a counterparty can tell "moved" from "never said".
func TestANewAddressSupersedesWithoutErasing(t *testing.T) {
	s := witnessWithStore(t)
	postEndpointRecord(t, s, map[string]any{
		"aid": "EController", "record": locSchemeRecord("EOld", "https://old.relay-a.test")})
	postEndpointRecord(t, s, map[string]any{
		"aid": "EController", "record": locSchemeRecord("ENew", "https://new.relay-b.test")})

	records, err := s.DataStore.GetEndpointRecords("EController")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected both statements to be held, got %d", len(records))
	}
}

// A counterparty holding a dead URL has no authenticated channel left to ask
// through, so lookup is public. The records are individually signed, so this
// discloses nothing the controller did not choose to publish.
func TestEndpointLookupIsReachableWithoutCredentials(t *testing.T) {
	s := witnessWithStore(t)
	postEndpointRecord(t, s, map[string]any{
		"aid": "EController", "record": locSchemeRecord("ELookup", "https://k7f2pq9r.relay-a.test")})

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("controller_aid", "EController")
	r := httptest.NewRequest(http.MethodGet, "/api/witness/endpoint/EController", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	s.handleWitnessEndpointLookup(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("lookup failed: status %d body %s", w.Code, w.Body.String())
	}
	var out struct {
		Count   int `json:"count"`
		Records []struct {
			URL string `json:"url"`
		} `json:"records"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Count != 1 || len(out.Records) != 1 {
		t.Fatalf("expected one record back, got %d", out.Count)
	}
	if out.Records[0].URL != "https://k7f2pq9r.relay-a.test" {
		t.Errorf("wrong address returned: %q", out.Records[0].URL)
	}
}
