package relayproto

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The relay and the Identity Agent read the same private list: the relay by
// path, the Identity Agent by the route pattern its router matched.
func TestThePrivateListAnswersTheSameBothWays(t *testing.T) {
	aid := "E" + strings.Repeat("a", 43)
	for _, c := range []struct {
		pattern, method, path string
	}{
		{"GET /oobi/{aid}", "GET", "/oobi/" + aid},
		{"GET /public/oobi/{aid}", "GET", "/public/oobi/" + aid},
		{"HEAD /{aid}/kel", "HEAD", "/" + aid + "/kel"},
		{"POST /didcomm", "POST", "/didcomm"},
	} {
		if !IsPrivateRoute(c.pattern) || !PrivateMayReach(c.method, c.path) {
			t.Errorf("%s / %s %s disagree or are refused", c.pattern, c.method, c.path)
		}
	}
	for _, p := range []string{"GET /*", "POST /api/sealed", "GET /api/health", "DELETE /didcomm"} {
		if IsPrivateRoute(p) {
			t.Errorf("%s is a private route", p)
		}
	}
}

func TestABrowserLoadingAPageIsRecognised(t *testing.T) {
	cases := []struct {
		h    map[string]string
		want bool
	}{
		{map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, true},
		{map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"}, true},
		{map[string]string{"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "embed"}, true},
		{map[string]string{"Accept": "text/html,application/xhtml+xml"}, true},
		{map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Accept": "*/*"}, false},
		{map[string]string{"Accept": "application/json"}, false},
		{map[string]string{}, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/oobi/x", nil)
		for k, v := range c.h {
			r.Header.Set(k, v)
		}
		if got := IsBrowserNavigation(r); got != c.want {
			t.Errorf("%v: %v, want %v", c.h, got, c.want)
		}
	}
}

func TestOnlyProtocolMediaTypesPass(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/json":                    true,
		"application/json; charset=utf-8":     true,
		"application/did+json; charset=utf-8": true,
		"application/didcomm-envelope+json":   true,
		"application/cesr":                    true,
		"application/octet-stream":            true,
		"text/plain; charset=utf-8":           true,
		"text/html":                           false,
		"TEXT/HTML; charset=utf-8":            false,
		"application/xhtml+xml":               false,
		"image/svg+xml":                       false,
		"application/pdf":                     false,
		"text/javascript":                     false,
		"application/javascript":              false,
		"text/xml":                            false,
		"multipart/x-mixed-replace":           false,
		"":                                    false,
		"garbage":                             false,
	} {
		if got := IsProtocolMediaType(ct); got != want {
			t.Errorf("%q: %v, want %v", ct, got, want)
		}
	}
}

// A modified Identity Agent answering a protocol route with a page, a
// redirect, or headers that send a browser elsewhere gets none of it past the
// relay, at either kind of address.
func TestAnIdentityAgentCannotServeAPageThroughTheRelay(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.route("a1b2.relay.test", id.aid, Preamble{Allocation: "priv-1", Mode: ModePrivate, Host: "a1b2.relay.test"})
	answer := map[string]func(http.ResponseWriter){
		"html": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<form>password</form>")
		},
		"sniffed": func(w http.ResponseWriter) { io.WriteString(w, "<!doctype html><form>password</form>") },
		"svg": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "image/svg+xml")
			io.WriteString(w, "<svg/>")
		},
		"redirect": func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://elsewhere.test/")
			w.WriteHeader(http.StatusFound)
		},
	}
	var kind atomic.Value
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		answer[kind.Load().(string)](w)
	}))
	for _, host := range []string{"acme.relay.test", "a1b2.relay.test"} {
		for k := range answer {
			kind.Store(k)
			req, _ := http.NewRequest("GET", r.front.URL+"/oobi/"+id.aid, nil)
			resp := r.do(host, req)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "<") ||
				resp.Header.Get("Location") != "" || strings.Contains(resp.Header.Get("Content-Type"), "html") {
				t.Errorf("%s answer %s: status %d, type %q, location %q, body %q", host, k,
					resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Location"), body)
			}
		}
	}
}

// What does pass carries the headers that stop a browser reading it as
// anything else, and none of the headers that could send it somewhere.
func TestAProtocolAnswerIsSealedForBrowsers(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Content-Security-Policy", "script-src *")
		h.Set("X-Content-Type-Options", "sniff")
		h.Set("Refresh", "0; url=https://elsewhere.test/")
		h.Set("Link", "<https://elsewhere.test/x.js>; rel=preload")
		h.Set("Content-Location", "https://elsewhere.test/")
		h.Set("Service-Worker-Allowed", "/")
		h.Add("Set-Cookie", "a=1; Domain=relay.test")
		h.Add("Set-Cookie", "b=2")
		io.WriteString(w, `{}`)
	}))
	req, _ := http.NewRequest("GET", r.front.URL+"/api/health", nil)
	resp := r.do("acme.relay.test", req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for name, want := range ProtocolResponseHeaders {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"Refresh", "Link", "Content-Location", "Service-Worker-Allowed"} {
		if v := resp.Header.Get(name); v != "" {
			t.Errorf("%s passed: %q", name, v)
		}
	}
	if c := resp.Header.Values("Set-Cookie"); len(c) != 1 || c[0] != "b=2" {
		t.Errorf("cookies passed: %q", c)
	}
}

// A browser loading a page at an address is never carried to the Identity
// Agent, even at a route the address passes.
func TestABrowserLoadingAPageNeverReachesTheIdentityAgent(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	var reached atomic.Bool
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	req, _ := http.NewRequest("GET", r.front.URL+"/oobi/"+id.aid, nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp := r.do("acme.relay.test", req)
	resp.Body.Close()
	if reached.Load() || resp.StatusCode == http.StatusOK {
		t.Fatalf("a page load reached the Identity Agent (status %d)", resp.StatusCode)
	}
}

func TestTheVisitorPageIsTheRelaysOwn(t *testing.T) {
	for link, want := range map[string]string{
		"":                                  DefaultVisitorLink,
		"http://plain.test/":                DefaultVisitorLink,
		"javascript:alert(1)":               DefaultVisitorLink,
		"https://operator.test/get?a=1&b=2": "https://operator.test/get?a=1&amp;b=2",
		`https://operator.test/"><script>`:  "https://operator.test/%22%3e%3cscript%3e",
	} {
		w := httptest.NewRecorder()
		ServeVisitorPage(w, httptest.NewRequest("GET", "/oobi/<script>x</script>", nil), link)
		body := w.Body.String()
		if !strings.Contains(body, `href="`+want+`"`) {
			t.Errorf("link %q: page does not lead to %q:\n%s", link, want, body)
		}
		if strings.Contains(body, "<script") {
			t.Errorf("link %q: the page carries a script", link)
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("CSP %q", csp)
		}
	}
}
