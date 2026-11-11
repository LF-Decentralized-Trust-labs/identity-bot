package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"identity-agent-core/store"
)

// rootAgent holds its own identity with a stored one-event log, and EContact as
// an accepted contact whose requests are signed by seed.
func rootAgent(t *testing.T, seed []byte) *CoreServer {
	t.Helper()
	s := contactAndAgent(t, "accepted", seed)
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: "ERootIdentityAID0001", PublicKey: "DRoot", EventCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID: "ERootIdentityAID0001", SequenceNumber: 0, EventType: "icp", PublicKey: "DRoot",
		EventJSON:     `{"v":"KERI10JSON000256_","t":"icp","i":"ERootIdentityAID0001","s":"0"}`,
		CesrSignature: "AAsig", Timestamp: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

// What the asking side digests: the "kel" the route serves, decoded.
func asServedByTheRoute(t *testing.T, s *CoreServer) []map[string]interface{} {
	t.Helper()
	rec := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(rec, remote("GET", "/public/oobi/ERootIdentityAID0001", ""))
	var doc struct {
		KEL []map[string]interface{} `json:"kel"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &doc) != nil || len(doc.KEL) == 0 {
		t.Fatalf("the route did not serve the root log: %d %s", rec.Code, rec.Body.String())
	}
	return doc.KEL
}

// Failed before: servedLog held the bare parsed event of each entry while the
// route serves the stored records (event_json, cesr_signature, timestamps),
// which is what the asker digests, so the two could never agree for the
// agent's own identity.
func TestTheDigestOfOurRootLogIsTheOneTheRouteServes(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 3
	s := rootAgent(t, seed)
	served := asServedByTheRoute(t, s)

	got, ok := s.servedLog("ERootIdentityAID0001", remote("POST", "/public/kel-check", ""))
	if !ok {
		t.Fatal("our own identity's log was not served to a contact")
	}
	if a, b := mustRawJSON(t, got), mustRawJSON(t, served); a != b {
		t.Fatalf("servedLog differs from what the route serves:\n%s\n%s", a, b)
	}
}

func mustRawJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Failed before (removing the exclusion survived): at a private address the root
// identity is not known, so a contact asking about it there gets no log.
func TestOurRootLogIsNotServedAtAPrivateAddress(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 4
	s := rootAgent(t, seed)
	r := remote("POST", "/public/kel-check", "")
	if _, ok := s.servedLog("ERootIdentityAID0001", r); !ok {
		t.Fatal("the root log should be served at a public address")
	}
	// A relayed request with no allocation known is at a private address.
	priv := r.WithContext(relayproto.ContextWithPreamble(r.Context(), relayproto.Preamble{Allocation: "private"}))
	if !s.reachedAtPrivateAddress(priv) {
		t.Fatal("the test's request is not at a private address")
	}
	if kel, ok := s.servedLog("ERootIdentityAID0001", priv); ok || kel != nil {
		t.Fatalf("the root log was served at a private address: %v", kel)
	}
}
