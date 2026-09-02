package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/drivers"
)

// A computer asking to act for an identity checks who is actually there.
//
// Everything else in this area is the Identity Agent satisfying itself about
// the machine. This runs the other way, and without it the machine wrote down
// whatever identifier it was told — believed by every later launch, because
// that is what a recorded answer is for.
func TestAnIdentityElsewhereIsCheckedAgainstItsPublishedHistory(t *testing.T) {
	ask := func(t *testing.T, s *CoreServer, body string) verifyIdentityResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/verify/identity-elsewhere",
			strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		s.handleVerifyAnIdentityElsewhere(rec, req)
		var out verifyIdentityResponse
		json.NewDecoder(rec.Body).Decode(&out)
		return out
	}

	t.Run("an address publishing nothing is not verified", func(t *testing.T) {
		s := agentWithNoIdentity(t)
		s.KeriDriver = drivers.NewKeriDriver()
		empty := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }))
		defer empty.Close()

		out := ask(t, s, `{"aid":"ESOMEBODY","oobi_url":"`+empty.URL+`"}`)
		if out.Verified {
			t.Fatal("an address that published no key history was accepted")
		}
		if out.Why == "" {
			t.Error("no reason, which somebody cannot act on")
		}
	})

	t.Run("an address nothing answers at is not verified", func(t *testing.T) {
		s := agentWithNoIdentity(t)
		s.KeriDriver = drivers.NewKeriDriver()
		out := ask(t, s, `{"aid":"ESOMEBODY","oobi_url":"http://127.0.0.1:9/nope"}`)
		if out.Verified {
			t.Fatal("an unreachable address was accepted")
		}
	})

	t.Run("a computer with no engine says so rather than refusing", func(t *testing.T) {
		// Different answers. "Do not trust that" and "this computer cannot
		// tell" lead to the same caution and to different words, and a caller
		// that could not distinguish them would report the wrong one.
		s := agentWithNoIdentity(t)
		s.KeriDriver = nil
		req := httptest.NewRequest(http.MethodPost, "/api/verify/identity-elsewhere",
			strings.NewReader(`{"aid":"ESOMEBODY","oobi_url":"https://x.test/oobi"}`))
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		s.handleVerifyAnIdentityElsewhere(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("expected this computer to say it cannot check, got %d %s",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("naming no identity or no address is refused", func(t *testing.T) {
		s := agentWithNoIdentity(t)
		s.KeriDriver = drivers.NewKeriDriver()
		for _, body := range []string{
			`{"aid":"","oobi_url":"https://x.test/oobi"}`,
			`{"aid":"ESOMEBODY","oobi_url":""}`,
		} {
			req := httptest.NewRequest(http.MethodPost, "/api/verify/identity-elsewhere",
				strings.NewReader(body))
			req.RemoteAddr = "127.0.0.1:1234"
			rec := httptest.NewRecorder()
			s.handleVerifyAnIdentityElsewhere(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s was not refused: %d", body, rec.Code)
			}
		}
	})
}
