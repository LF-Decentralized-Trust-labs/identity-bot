package relayproto

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

// What an answer through a relay may be (ADR-048, "Amendment: an address
// carries only the protocol").
//
// A relay passes an Identity Agent's answer only if it is data in one of the
// protocol's own types, and it forces the headers that stop a browser from
// treating that data as anything else. The relay checks the type of what is
// said, never what is said: it reads no body.

// ProtocolMediaTypes are the media types an answer through a relay may carry.
// Any application/...+json type passes as JSON does.
var ProtocolMediaTypes = []string{
	"application/json",
	"application/cesr",
	"application/octet-stream",
	// What a refusal is written as (http.Error): shown as text, never run.
	"text/plain",
}

// ProtocolResponseHeaders are set on every answer a relay passes, replacing
// whatever the Identity Agent sent: no type sniffing, nothing loaded or run,
// no framing, and nothing a cache in front may keep. The same URL answers a
// browser loading a page with the relay's own page, and a cache that ignores
// Vary (as content delivery networks commonly do) must never hand one in
// place of the other.
var ProtocolResponseHeaders = map[string]string{
	"X-Content-Type-Options":  "nosniff",
	"Content-Security-Policy": "default-src 'none'; sandbox; frame-ancestors 'none'",
	"X-Frame-Options":         "DENY",
	"Cache-Control":           "private, no-store",
}

// passedResponseHeaders are the only headers of an Identity Agent's answer a
// relay passes; every other header is dropped. Anything a browser could act
// on (a redirect, a preload, a sign-in prompt, a cache lifetime, a download
// name) is absent because it is not here, not because it was thought of.
var passedResponseHeaders = []string{
	"Content-Type",
	"Content-Length",
	"Content-Encoding",
	"Etag",
	"Last-Modified",
	"Date",
	"Vary",
	"Retry-After",
	// A relying party's page may call a public identity's sign-in routes, and
	// read their answers, from its own origin. Never with credentials.
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
}

// passedResponseHeaderPrefixes pass a whole family: the protocol's own
// key-state headers.
var passedResponseHeaderPrefixes = []string{"X-Keri-"}

// passedUpgradeHeaders are what a relay passes on a protocol switch, and
// nothing else.
var passedUpgradeHeaders = []string{"Upgrade", "Connection"}

var passedUpgradeHeaderPrefixes = []string{"Sec-Websocket-"}

// ErrNotProtocol is why a relay refused an Identity Agent's answer.
var ErrNotProtocol = errors.New("the Identity Agent answered with something other than protocol data")

// IsProtocolMediaType reports whether a Content-Type value is one an answer
// through a relay may carry.
func IsProtocolMediaType(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	if strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json") {
		return true
	}
	for _, t := range ProtocolMediaTypes {
		if mt == t {
			return true
		}
	}
	return false
}

// CheckProtocolResponse applies the rule to an Identity Agent's answer at an
// address in mode, and makes it safe to pass. It refuses a redirect, or a body
// in any type but the protocol's, or an answer naming more than one type;
// keeps only the headers in passedResponseHeaders; and sets
// ProtocolResponseHeaders. A cookie passes only at a public address, and only
// one held by that address alone. A websocket is accepted only at a public
// address, where the identity's own front ends keep one open; a browser cannot
// load a page from one.
func CheckProtocolResponse(resp *http.Response, mode Mode) error {
	switch {
	case resp.StatusCode == http.StatusSwitchingProtocols:
		if mode != ModePublic {
			return fmt.Errorf("%w: a protocol switch", ErrNotProtocol)
		}
	case resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.StatusCode != http.StatusNotModified:
		return fmt.Errorf("%w: a redirect", ErrNotProtocol)
	}
	h := resp.Header
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// What follows is the websocket's, not a body.
		keepOnly(h, passedUpgradeHeaders, passedUpgradeHeaderPrefixes)
		return nil
	}
	// Exactly one type. Browsers differ in which of two they believe, so a
	// second one is how a page would hide behind a protocol type.
	types := h.Values("Content-Type")
	switch {
	case len(types) > 1:
		return fmt.Errorf("%w: more than one Content-Type", ErrNotProtocol)
	case len(types) == 0 || types[0] == "":
		if hasBody(resp) {
			return fmt.Errorf("%w: a body with no type", ErrNotProtocol)
		}
	case !IsProtocolMediaType(types[0]):
		return fmt.Errorf("%w: %s", ErrNotProtocol, types[0])
	}
	cookies := h.Values("Set-Cookie")
	keepOnly(h, passedResponseHeaders, passedResponseHeaderPrefixes)
	for name, v := range ProtocolResponseHeaders {
		h.Set(name, v)
	}
	h.Add("Vary", "Sec-Fetch-Mode")
	h.Add("Vary", "Sec-Fetch-Dest")
	h.Add("Vary", "Accept")
	// Every private address shares one origin, so a cookie set at one would
	// reach the others. At a public address a cookie is the address's own.
	if mode == ModePublic {
		for _, c := range cookies {
			if parsed, err := http.ParseSetCookie(c); err == nil && parsed.Domain == "" {
				h.Add("Set-Cookie", c)
			}
		}
	}
	return nil
}

// keepOnly deletes every header in h not named in names or starting with one
// of prefixes. Names are compared in canonical form.
func keepOnly(h http.Header, names, prefixes []string) {
	for name := range h {
		if !headerPassed(name, names, prefixes) {
			delete(h, name)
		}
	}
}

func headerPassed(name string, names, prefixes []string) bool {
	name = http.CanonicalHeaderKey(name)
	for _, n := range names {
		if name == http.CanonicalHeaderKey(n) {
			return true
		}
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, http.CanonicalHeaderKey(p)) {
			return true
		}
	}
	return false
}

func hasBody(resp *http.Response) bool {
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return false
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return false
	}
	return resp.ContentLength != 0
}
