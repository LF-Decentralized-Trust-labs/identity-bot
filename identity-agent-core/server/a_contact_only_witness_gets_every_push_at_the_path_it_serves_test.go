package server

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// A contact witnessing for somebody is an Identity Agent, and serves everything
// under /api. Key-log events and registry events are both pushed to it, and
// both must go to the path it serves: a push to a path it does not serve is
// answered 404, which looks like a witness that is down.
func TestKeyLogAndRegistryPushesBothReachAContactOnlyWitnessUnderApi(t *testing.T) {
	w := newPushWorld(t)

	target, _ := url.Parse(w.bob.base)
	proxy := httputil.NewSingleHostReverseProxy(target)
	var mu sync.Mutex
	var posted []string
	front := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			posted = append(posted, r.URL.Path)
			mu.Unlock()
		}
		proxy.ServeHTTP(rw, r)
	}))
	t.Cleanup(front.Close)
	w.contactAt(front.URL)

	w.issue()
	w.eventually(func() bool { n, _ := w.bobServes(); return n == 2 && len(w.pending()) == 0 },
		"the witness should come to hold the registry events through the path it serves")

	mu.Lock()
	defer mu.Unlock()
	var keyLog, tel int
	for _, p := range posted {
		if !strings.HasPrefix(p, "/api/witness/") {
			t.Errorf("a push went to %q, which a contact-only witness does not serve", p)
		}
		switch {
		case p == "/api/witness/event":
			keyLog++
		case p == "/api/witness/tel/"+w.aid:
			tel++
		}
	}
	if keyLog == 0 || tel == 0 {
		t.Fatalf("expected key-log and registry pushes, saw %d and %d: %v", keyLog, tel, posted)
	}
}
