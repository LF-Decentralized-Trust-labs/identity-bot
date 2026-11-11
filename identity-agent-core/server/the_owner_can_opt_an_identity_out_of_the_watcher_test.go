package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The route that sets an opt-out is owner-only, takes effect on the public
// routes at once, and can be undone.
func TestOwnerSetsAndClearsAWatcherOptOut(t *testing.T) {
	const aid = "EOptAID"
	s := watcherAgent(t, aid, 1, "Esecretdigest")
	asAPublicWatcherWithAContact(t, s)
	router := s.buildRouter()
	serve := func(m, p, b string, own bool) (int, string) {
		req := remote(m, p, b)
		if own {
			req = local(m, p, b)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, _ := serve("PUT", "/api/watcher/opt-out", `{"aid":"`+aid+`","opted_out":true}`, false); code != 401 && code != 403 {
		t.Fatalf("a stranger set an opt-out: %d", code)
	}
	if _, body := serve("GET", "/public/kel-digest?aid="+aid+"&seq=1", "", false); !strings.Contains(body, "Esecretdigest") {
		t.Fatalf("setup: %s", body)
	}
	if code, body := serve("PUT", "/api/watcher/opt-out", `{"aid":"`+aid+`","opted_out":true}`, true); code != 200 {
		t.Fatalf("owner could not opt out: %d %s", code, body)
	}
	if _, body := serve("GET", "/api/watcher/opt-out?aid="+aid, "", true); !strings.Contains(body, `"opted_out":true`) {
		t.Fatalf("not reported: %s", body)
	}
	if _, body := serve("GET", "/public/kel-digest?aid="+aid+"&seq=1", "", false); strings.Contains(body, "Esecretdigest") {
		t.Fatalf("digest still disclosed: %s", body)
	}
	if code, _ := serve("PUT", "/api/watcher/opt-out", `{"aid":"`+aid+`","opted_out":false}`, true); code != 200 {
		t.Fatal("owner could not opt back in")
	}
	if _, body := serve("GET", "/public/kel-digest?aid="+aid+"&seq=1", "", false); !strings.Contains(body, "Esecretdigest") {
		t.Fatalf("opt back in did not restore: %s", body)
	}
}
