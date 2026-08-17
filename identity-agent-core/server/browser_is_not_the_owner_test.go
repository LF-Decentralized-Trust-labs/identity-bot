package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A web page is not the owner, however local its connection looks.
//
// The rule used to be "loopback and no forwarding headers is the owner", which
// was written for a native client on the machine the user is sitting at. A page
// loaded from any website reaches 127.0.0.1 the same way, so visiting a page was
// enough to be believed — and enough to read the roster, the invitation secrets
// and the identity.
//
// The cases below are the distinction the rule now makes. They are written
// against the headers a browser actually sends, because those are the evidence:
// Origin and the Sec-Fetch-* family are forbidden header names, set by the
// browser itself, and page script cannot change or remove them.
func TestBrowserIsNotTheLocalOwner(t *testing.T) {
	cases := []struct {
		name    string
		remote  string
		headers map[string]string
		owner   bool
	}{
		{
			name:   "a native client on this machine is the owner",
			remote: "127.0.0.1:52001",
			owner:  true,
		},
		{
			name:   "a page fetching cross-site is not, however loopback it looks",
			remote: "127.0.0.1:52002",
			headers: map[string]string{
				"Origin":         "https://evil.example",
				"Sec-Fetch-Site": "cross-site",
				"Sec-Fetch-Mode": "cors",
			},
			owner: false,
		},
		{
			name:   "an Origin alone is enough to disqualify",
			remote: "127.0.0.1:52003",
			headers: map[string]string{
				"Origin": "https://evil.example",
			},
			owner: false,
		},
		{
			// A no-cors fetch gets an opaque response the page cannot read, but
			// it still reaches the handler and can still cause a write. It is
			// the request that has to be refused, not the reading of the reply.
			name:   "a no-cors fetch is refused as well",
			remote: "127.0.0.1:52004",
			headers: map[string]string{
				"Sec-Fetch-Mode": "no-cors",
				"Sec-Fetch-Dest": "empty",
			},
			owner: false,
		},
		{
			// Typing the address into the bar sends Sec-Fetch-Site: none, so the
			// site test alone would let it through — but it is still a browser,
			// and the API is not a thing to be browsed. Sec-Fetch-Dest catches
			// it. The owner's own client does not go through a browser at all.
			name:   "a typed-in address is still a browser, so still not the owner",
			remote: "127.0.0.1:52005",
			headers: map[string]string{
				"Sec-Fetch-Site": "none",
				"Sec-Fetch-Mode": "navigate",
				"Sec-Fetch-Dest": "document",
			},
			owner: false,
		},
		{
			name:   "a caller from the network is not the owner",
			remote: "192.168.0.7:52006",
			owner:  false,
		},
		{
			// A tunnel terminates locally, so the connection looks like
			// loopback. The forwarding header is what gives it away.
			name:   "a request through a tunnel is not the owner",
			remote: "127.0.0.1:52007",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.9",
			},
			owner: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/employees", nil)
			r.RemoteAddr = c.remote
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			if got := isLocalOwnerRequest(r); got != c.owner {
				t.Fatalf("isLocalOwnerRequest = %v, want %v", got, c.owner)
			}
		})
	}
}

// A foreign origin is not granted cross-origin access.
//
// This exists because the first attempt at the denial was
// `AllowedOrigins: []string{}`, which reads as "no origins" and means the
// opposite: the library documents an empty list as "Default is all origins"
// (go-chi/cors, cors.go). The config looked like a denial, the comment above
// it said it was one, and every origin was still answered with `*`. A claim
// about behaviour that nothing exercises is a guess, so this exercises it.
func TestForeignOriginGetsNoCrossOriginGrant(t *testing.T) {
	h := corsMiddlewareForTest()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))

	t.Run("an actual request is not readable cross-origin", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/api/employees", nil)
		r.Header.Set("Origin", "https://unrelated.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("Access-Control-Allow-Origin = %q, want it absent", got)
		}
	})

	t.Run("a preflight is not granted either", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodOptions, "/api/employees", nil)
		r.Header.Set("Origin", "https://unrelated.example")
		r.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("preflight Access-Control-Allow-Origin = %q, want it absent", got)
		}
		if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Fatalf("preflight Access-Control-Allow-Credentials = %q, want it absent", got)
		}
	})
}

func corsMiddlewareForTest() func(http.Handler) http.Handler { return corsPolicy() }
