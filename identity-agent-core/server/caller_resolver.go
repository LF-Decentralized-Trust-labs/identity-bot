package server

import (
	"net"
	"net/http"

	"identity-agent-core/sandbox"
)

// CallerResolver resolves WHO is calling the endpoint and WHAT capability scopes they
// hold, from the request — the seam delegated-identity (caller AID + ACDC scopes)
// implements. The default derives only local-owner-vs-remote from the connection;
// when delegated-identity resolution is implemented it is injected via
// CoreServer.CallerResolver and fills the AID + granted scopes, with no handler change.
type CallerResolver interface {
	Resolve(r *http.Request) sandbox.CallerContext
}

// loopbackCallerResolver is the default: a request from the loopback interface is the
// local owner; anything else is a remote caller with no granted scopes (default-deny).
type loopbackCallerResolver struct{}

func (loopbackCallerResolver) Resolve(r *http.Request) sandbox.CallerContext {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return sandbox.CallerContext{Remote: !sandbox.IsLoopbackHost(host)}
}

// resolveCaller returns the configured CallerResolver's result, or the loopback default.
func (s *CoreServer) resolveCaller(r *http.Request) sandbox.CallerContext {
	if s.CallerResolver != nil {
		return s.CallerResolver.Resolve(r)
	}
	return loopbackCallerResolver{}.Resolve(r)
}
