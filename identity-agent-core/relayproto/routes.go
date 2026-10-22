package relayproto

import (
	"net/http"
	"regexp"
	"strings"
)

// What reaches an Identity Agent through a relay (ADR-048 §6, and its
// amendment "An address carries only the protocol").
//
// At either kind of address, a browser loading a page never reaches the
// Identity Agent: the relay answers it with its own visitor page. A private
// address also passes only the routes in PrivateRoutes. A public address
// passes any other request, because the identity's own front ends (a machine
// acting for its owner, say) reach it there; what it may answer is bounded
// instead, by CheckProtocolResponse.
//
// A pattern is "METHOD /path". A segment in braces stands for exactly one path
// segment; {aid} must look like a KERI identifier. A GET route also passes
// HEAD. Paths match exactly: no trailing slash and no other spelling. This
// list is the only copy: a relay and an Identity Agent both read it here.

// PrivateRoutes are what a private address passes: the identity's artifacts
// to the counterparty the address was made for, that counterparty's messages,
// and its key registration.
var PrivateRoutes = []string{
	"GET /oobi/{aid}",
	"GET /public/oobi/{aid}",
	"GET /{aid}/oobi",
	"GET /{aid}/did.json",
	"GET /public/{aid}/did.json",
	"GET /{aid}/kel",
	"GET /{aid}/keri.cesr",
	"POST /didcomm",
	"POST /_register",
	"POST /public/_register",
}

var aidSegment = regexp.MustCompile(`^[A-Za-z0-9_-]{44,}$`)

// IsPrivateRoute reports whether pattern ("METHOD /pattern", as an Identity
// Agent's router names the route it matched) is one a private address passes.
// HEAD counts as GET.
func IsPrivateRoute(pattern string) bool {
	if rest, ok := strings.CutPrefix(pattern, "HEAD "); ok {
		pattern = "GET " + rest
	}
	for _, p := range PrivateRoutes {
		if p == pattern {
			return true
		}
	}
	return false
}

// PrivateMayReach reports whether a private address passes method at path, as
// a relay sees it before the Identity Agent does.
func PrivateMayReach(method, path string) bool {
	if method == http.MethodHead {
		method = http.MethodGet
	}
	for _, p := range PrivateRoutes {
		if routeMatches(p, method, path) {
			return true
		}
	}
	return false
}

func routeMatches(pattern, method, path string) bool {
	pm, pp, _ := strings.Cut(pattern, " ")
	if pm != method || !strings.HasPrefix(path, "/") {
		return false
	}
	want := strings.Split(pp[1:], "/")
	got := strings.Split(path[1:], "/")
	if len(want) != len(got) {
		return false
	}
	for i, w := range want {
		switch g := got[i]; {
		case w == "{aid}":
			if !aidSegment.MatchString(g) {
				return false
			}
		case strings.HasPrefix(w, "{"):
			if g == "" {
				return false
			}
		case w != g:
			return false
		}
	}
	return true
}

// requestAllowed is what the relay passes to the Identity Agent at an address
// in mode.
func requestAllowed(r *http.Request, mode Mode) bool {
	if IsBrowserNavigation(r) {
		return false
	}
	if mode != ModePrivate {
		return true
	}
	// Its exact path, with no percent-encoding that could be read two ways,
	// and no protocol upgrade.
	if r.URL.EscapedPath() != r.URL.Path || r.Header.Get("Upgrade") != "" {
		return false
	}
	return PrivateMayReach(r.Method, r.URL.Path)
}

// IsBrowserNavigation reports whether r is a browser loading a page: following
// a link, typing an address, or framing one. Such a request never reaches an
// Identity Agent through a relay; the relay answers it with its own visitor
// page instead.
//
// A browser says what it is loading in Sec-Fetch-Dest and Sec-Fetch-Mode. One
// too old to send them is recognised by asking for HTML. An Identity Agent, a
// relying party's script and a command-line client send neither.
func IsBrowserNavigation(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document", "iframe", "frame", "embed", "object", "fencedframe":
		return true
	}
	switch r.Header.Get("Sec-Fetch-Mode") {
	case "navigate", "nested-navigate":
		return true
	case "":
		return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
	}
	return false
}
