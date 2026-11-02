package server

import (
	"context"
	"net/http"

	"identity-agent-core/avatar"
)

// maxPhotoBody bounds a request that carries a photo as base64 inside JSON:
// avatar.MaxSourceBytes raw is 4/3 of that encoded, plus room for the JSON
// around it. Derived from the bound the avatar decoder applies, so the two
// move together.
const maxPhotoBody = avatar.MaxSourceBytes*4/3 + 64<<10

// signedBodyBounds are the routes whose signed body may exceed
// maxSignedBodyBytes, each at the bound its own handler applies. Keys are
// "METHOD pattern", as classify takes them. A route not listed gets the default.
var signedBodyBounds = map[string]int64{
	"POST /api/recovery/start":         maxRecoveryBody,
	"POST /api/recovery/verify":        maxRecoveryBody,
	"PUT /api/profile":                 maxPhotoBody,
	"POST /api/profile/avatar/stylize": maxPhotoBody,
}

type signedBodyBoundKey struct{}

// withSignedBodyBound records, on a request the gate has matched to pattern,
// how much of its body may be read before the signature is checked.
func withSignedBodyBound(r *http.Request, pattern string) *http.Request {
	limit, ok := signedBodyBounds[r.Method+" "+pattern]
	if !ok {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), signedBodyBoundKey{}, limit))
}

// signedBodyBoundFor is the bound for r's route, as the gate recorded it, or
// the default for a request that never passed the gate.
func signedBodyBoundFor(r *http.Request) int64 {
	if limit, ok := r.Context().Value(signedBodyBoundKey{}).(int64); ok {
		return limit
	}
	return maxSignedBodyBytes
}
