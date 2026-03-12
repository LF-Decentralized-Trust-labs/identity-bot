package sandbox

import "net/http"

// credentialHeaders is the list of HTTP response headers that may carry
// authentication material. They are stripped before the response is
// forwarded to a sandboxed container so that session tokens, cookies, and
// auth challenges never reach untrusted code.
var credentialHeaders = []string{
	"Set-Cookie",
	"WWW-Authenticate",
	"Proxy-Authenticate",
	"Authorization",
	"X-Api-Key",
	"X-Auth-Token",
	"X-Access-Token",
	"X-Session-Token",
}

// ScrubResponseHeaders removes well-known credential-bearing headers from an
// HTTP response header map in-place. It is called by the MITM proxy and the
// plain-HTTP proxy path before copying headers to the container-facing writer.
func ScrubResponseHeaders(h http.Header) {
	for _, key := range credentialHeaders {
		h.Del(key)
	}
}
