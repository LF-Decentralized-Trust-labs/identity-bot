package relayproto

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
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
		h.Add("Set-Cookie", "c=1; domain = .relay.test")
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
	if v := strings.Join(resp.Header.Values("Vary"), ","); !strings.Contains(v, "Sec-Fetch-Mode") {
		t.Errorf("a cache could hand this answer to a browser loading a page: Vary %q", v)
	}
	// None at all: a browser reads "domain = .relay.test" as the whole apex
	// where a parser may not, so no cookie is safer than a filtered one.
	if c := resp.Header.Values("Set-Cookie"); len(c) != 0 {
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
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("the visitor page may be cached: %q", cc)
		}
	}
}

// Browsers too old to say what they are loading still name both HTML types
// when they load a page; a client that merely lists HTML among others does
// not, and reaches the Identity Agent.
func TestOnlyABrowsersPageAcceptIsAPageLoad(t *testing.T) {
	for accept, want := range map[string]bool{
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8":                       true,
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8": true,
		// Java's HttpURLConnection, asking for did.json.
		"text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2": false,
		"text/html;q=0, application/xhtml+xml":                 false,
		"text/html":                                            false,
		"application/json, text/plain, */*":                    false,
	} {
		r := httptest.NewRequest("GET", "/x/did.json", nil)
		r.Header.Set("Accept", accept)
		if got := IsBrowserNavigation(r); got != want {
			t.Errorf("Accept %q: page load %v, want %v", accept, got, want)
		}
	}
}

// Only the headers the protocol uses pass. Everything else an Identity Agent
// sends is dropped, whether or not anybody thought of it: a cache lifetime, a
// sign-in prompt, a download name, credentials across origins.
func TestOnlyTheProtocolsHeadersPass(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.route("a1b2.relay.test", id.aid, Preamble{Allocation: "priv-1", Mode: ModePrivate, Host: "a1b2.relay.test"})
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		h.Set("CDN-Cache-Control", "max-age=31536000")
		h.Set("Cloudflare-CDN-Cache-Control", "max-age=31536000")
		h.Set("Surrogate-Control", "max-age=31536000")
		h.Set("Expires", "Thu, 01 Jan 2099 00:00:00 GMT")
		h.Set("WWW-Authenticate", `Basic realm="sign in"`)
		h.Set("Proxy-Authenticate", `Basic realm="sign in"`)
		h.Set("Content-Disposition", `attachment; filename="invoice.html"`)
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Alt-Svc", `h3=":443"`)
		h.Set("Strict-Transport-Security", "max-age=63072000")
		h.Set("X-Keri-Keystate-Seq", "3")
		h.Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{}`)
	}))
	for _, host := range []string{"acme.relay.test", "a1b2.relay.test"} {
		req, _ := http.NewRequest("GET", r.front.URL+"/oobi/"+id.aid, nil)
		resp := r.do(host, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status %d", host, resp.StatusCode)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "private, no-store" {
			t.Errorf("%s: a cache may keep the answer: Cache-Control %q", host, cc)
		}
		for _, name := range []string{"CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control",
			"Expires", "WWW-Authenticate", "Proxy-Authenticate", "Content-Disposition",
			"Access-Control-Allow-Credentials", "Alt-Svc", "Strict-Transport-Security"} {
			if v := resp.Header.Get(name); v != "" {
				t.Errorf("%s: %s passed: %q", host, name, v)
			}
		}
		for _, name := range []string{"Access-Control-Allow-Origin", "X-Keri-Keystate-Seq"} {
			if resp.Header.Get(name) == "" {
				t.Errorf("%s: the protocol's %s was dropped", host, name)
			}
		}
		if cookies := resp.Header.Values("Set-Cookie"); len(cookies) != 0 {
			t.Errorf("%s: cookies passed: %q", host, cookies)
		}
	}
}

// An answer naming two types is refused: browsers differ in which they
// believe, so a page could hide behind a protocol type.
func TestAnAnswerWithTwoTypesIsRefused(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["Content-Type"] = []string{"application/json", "text/html"}
		io.WriteString(w, "<form>password</form>")
	}))
	req, _ := http.NewRequest("GET", r.front.URL+"/oobi/"+id.aid, nil)
	resp := r.do("acme.relay.test", req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "<form") {
		t.Fatalf("status %d, types %q, body %q", resp.StatusCode, resp.Header.Values("Content-Type"), body)
	}
}

// An informational answer reaches the caller before the final answer is
// checked, so none passes: an early hint's preload or cookie never arrives.
func TestNoEarlyAnswerPasses(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "<https://elsewhere.test/x.css>; rel=preload")
		w.Header().Set("Set-Cookie", "a=1; Domain=relay.test")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Del("Set-Cookie")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	var early []int
	req, _ := http.NewRequest("GET", r.front.URL+"/oobi/"+id.aid, nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error { early = append(early, code); return nil },
	}))
	resp := r.do("acme.relay.test", req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(early) != 0 {
		t.Errorf("early answers passed: %v", early)
	}
}

// A protocol switch at a public address keeps only what the switch needs.
func TestAProtocolSwitchCarriesOnlyItsOwnHeaders(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{
		"Upgrade":              {"websocket"},
		"Connection":           {"Upgrade"},
		"Sec-Websocket-Accept": {"x"},
		"Set-Cookie":           {"a=1"},
		"Link":                 {"<https://elsewhere.test/>; rel=preload"},
	}}
	if err := CheckProtocolResponse(resp, ModePublic); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Upgrade", "Connection", "Sec-Websocket-Accept"} {
		if resp.Header.Get(name) == "" {
			t.Errorf("%s dropped from a protocol switch", name)
		}
	}
	for _, name := range []string{"Set-Cookie", "Link"} {
		if v := resp.Header.Get(name); v != "" {
			t.Errorf("%s passed on a protocol switch: %q", name, v)
		}
	}
	if err := CheckProtocolResponse(&http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}}, ModePrivate); err == nil {
		t.Error("a private address passed a protocol switch")
	}
}
