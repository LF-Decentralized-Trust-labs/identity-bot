package server

import (
	"net/http"
	"os"
	"strings"
)

// Learning where this agent is actually reached from.
//
// An agent behind a reverse proxy cannot work its own public address out. It
// sees a request arrive on loopback; the name, the scheme and the path prefix
// the person actually typed are known only to the proxy in front of it. Left to
// guess, it falls back to a local interface — and then publishes that address in
// its OOBI, handing counterparties somewhere that resolves nowhere.
//
// THIS IS OFF UNLESS TURNED ON, and that is the whole design.
//
// Forwarding headers are set by whoever sends the request. An agent that
// believed them from any caller could be told by a stranger that it lives at the
// stranger's address, and would then publish that as its own — so anybody
// resolving its OOBI would be sent there. Believing them is only safe when
// something in front is guaranteed to overwrite them, which is true of a proxy
// and false of a directly reachable agent.
//
// So the deployment states it. An agent that is always behind a proxy sets
// TRUST_FORWARDED_HEADERS=1; anything else ignores the headers entirely and
// keeps working out its address the way it always has.
func trustForwardedHeaders() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("TRUST_FORWARDED_HEADERS")))
	return v == "1" || v == "true"
}

// observedPublicBase builds the address a request actually arrived at, from
// what the proxy said about it.
//
// Returns "" when there is not enough to be sure. A partial answer is worse
// than none here: an address assembled from a guessed scheme or a missing host
// is one this agent would publish and nobody could reach.
func observedPublicBase(r *http.Request) string {
	host := firstForwarded(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		return ""
	}
	scheme := firstForwarded(r.Header.Get("X-Forwarded-Proto"))
	if scheme != "http" && scheme != "https" {
		// Not guessed. A proxy that forwards a host without saying how it was
		// reached has told us half of something, and choosing the other half
		// ourselves is how an agent ends up publishing http:// for a site
		// somebody reached over https.
		return ""
	}
	base := scheme + "://" + host
	if prefix := strings.TrimRight(firstForwarded(r.Header.Get("X-Forwarded-Prefix")), "/"); prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		base += prefix
	}
	return base
}

// firstForwarded takes the first value of a comma-separated forwarding header.
//
// These accumulate: two proxies in a chain append, so the header becomes
// "outermost, innermost". The first is the one the person actually reached.
func firstForwarded(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// learnAddressFromProxy records the address the first trusted request arrived
// at, and then stops looking.
//
// First one wins, deliberately. The address is published in OOBIs and handed to
// counterparties, so it should not move because one request happened to come
// through a different path — an identity that changes where it says it lives is
// one nobody can resolve reliably.
func (s *CoreServer) learnAddressFromProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trustForwardedHeaders() && s.EndpointService != nil &&
			s.EndpointService.Source() != "observed:proxy" {
			if base := observedPublicBase(r); base != "" {
				s.EndpointService.SetObservedURL(base)
			}
		}
		next.ServeHTTP(w, r)
	})
}
