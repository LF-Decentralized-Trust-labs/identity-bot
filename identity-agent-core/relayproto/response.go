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
// and no framing.
var ProtocolResponseHeaders = map[string]string{
	"X-Content-Type-Options":  "nosniff",
	"Content-Security-Policy": "default-src 'none'; sandbox; frame-ancestors 'none'",
	"X-Frame-Options":         "DENY",
}

// droppedResponseHeaders are never passed from an Identity Agent: each can
// send a browser somewhere, preload something, or widen what a script may
// control.
var droppedResponseHeaders = []string{
	"Refresh",
	"Link",
	"Location",
	"Content-Location",
	"Service-Worker-Allowed",
	"Clear-Site-Data",
}

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
// address in mode, and makes it safe to pass: it refuses a redirect, or a body
// in any type but the protocol's; then drops the headers a page could use and
// sets ProtocolResponseHeaders. It also drops a cookie scoped wider than the
// address it came from. A websocket is accepted only at a public address,
// where the identity's own front ends keep one open; a browser cannot load a
// page from one.
func CheckProtocolResponse(resp *http.Response, mode Mode) error {
	switch {
	case resp.StatusCode == http.StatusSwitchingProtocols:
		if mode != ModePublic {
			return fmt.Errorf("%w: a protocol switch", ErrNotProtocol)
		}
	case resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.StatusCode != http.StatusNotModified:
		return fmt.Errorf("%w: a redirect", ErrNotProtocol)
	}
	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// What follows is the websocket's, not a body.
	} else if ct == "" {
		if hasBody(resp) {
			return fmt.Errorf("%w: a body with no type", ErrNotProtocol)
		}
	} else if !IsProtocolMediaType(ct) {
		return fmt.Errorf("%w: %s", ErrNotProtocol, ct)
	}
	h := resp.Header
	for _, name := range droppedResponseHeaders {
		h.Del(name)
	}
	for name, v := range ProtocolResponseHeaders {
		h.Set(name, v)
	}
	if cookies := h.Values("Set-Cookie"); len(cookies) > 0 {
		h.Del("Set-Cookie")
		for _, c := range cookies {
			if parsed, err := http.ParseSetCookie(c); err == nil && parsed.Domain == "" {
				h.Add("Set-Cookie", c)
			}
		}
	}
	return nil
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
