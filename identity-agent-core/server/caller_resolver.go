package server

import (
	"net"
	"net/http"
	"strings"

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

// loopbackCallerResolver derives only local-vs-remote from the connection. It is no
// longer the default: a tunnel daemon connects from localhost, so loopback alone must
// not imply the owner. Kept for callers that explicitly want the structural check.
type loopbackCallerResolver struct{}

func (loopbackCallerResolver) Resolve(r *http.Request) sandbox.CallerContext {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return sandbox.CallerContext{Remote: !sandbox.IsLoopbackHost(host)}
}

// resolveCaller returns the configured CallerResolver's result, or the token-aware
// default: a positive credential (MCP token today, ACDC presentation when delegated
// identity lands) grants scopes; a genuinely local request (loopback AND no forwarding
// headers) is the owner; everything else is remote with no scopes.
func (s *CoreServer) resolveCaller(r *http.Request) sandbox.CallerContext {
	if s.CallerResolver != nil {
		return s.CallerResolver.Resolve(r)
	}
	return tokenAwareResolver{s: s}.Resolve(r)
}

// Header names carrying the "why" of a governed call. They ride outside the request
// body deliberately: the body is the capability's own arguments, its schema commonly
// forbids unknown properties, and the args hash must commit to exactly what the
// capability was asked to do — not to bookkeeping wrapped around it.
const (
	HeaderWorkItem = "X-Work-Item"
	HeaderReason   = "X-Reason"
)

// maxWhyLen bounds what a caller can write into the audit log through these headers.
// They are recorded verbatim and never authorize anything, so the only real risk they
// carry is unbounded growth of the record.
const maxWhyLen = 512

// applyCallerWhy copies the optional why-headers onto a resolved caller context. These
// are caller-supplied and never consulted for authorization — a caller can misstate its
// work item exactly as it can misstate a commit message. The fields that decide what is
// permitted (CallerAID, GrantSAID, DelegationChain) are proven elsewhere.
func applyCallerWhy(r *http.Request, cc *sandbox.CallerContext) {
	cc.WorkItem = clampWhy(r.Header.Get(HeaderWorkItem))
	cc.Reason = clampWhy(r.Header.Get(HeaderReason))
}

func clampWhy(v string) string {
	v = strings.TrimSpace(v)
	// Header values are written straight into the log; a newline would let a caller
	// forge what looks like a separate entry for anything reading it as text.
	v = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, v)
	if len(v) > maxWhyLen {
		return v[:maxWhyLen]
	}
	return v
}
