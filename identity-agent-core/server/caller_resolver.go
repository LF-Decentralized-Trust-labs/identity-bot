package server

import (
	"crypto/subtle"
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

// MOVED HERE 2026-08-31, from mcp_tokens.go. It is the default resolver for
// EVERY caller — the authorisation middleware asks it for scoped routes, and
// three handlers ask it directly — and it lived in a file named for MCP tokens
// only because bearer tokens were the first thing it had to understand. The
// name cost a reader real time working out whether a change to it was
// MCP-specific. It is not.
// tokenAwareResolver is the default CallerResolver: a valid MCP token grants its
// scopes (as a remote caller); a genuinely local request is the owner; everything
// else is remote with no scopes (default-deny at the gateway).
type tokenAwareResolver struct{ s *CoreServer }

func (t tokenAwareResolver) Resolve(r *http.Request) sandbox.CallerContext {
	cc := sandbox.CallerContext{
		Remote:        true,
		CorrelationID: requestCorrelationID(r),
		Transport:     "mcp",
	}
	if tok := bearerFrom(r); tok != "" {
		cc.AuthLevel = "bearer" // upgraded to "signed_request" if an envelope verifies
		presented := hashMCPToken(tok)
		mcpTokensMu.Lock()
		toks := t.s.loadMCPTokens()
		mcpTokensMu.Unlock()
		for _, entry := range toks {
			if subtle.ConstantTimeCompare([]byte(entry.Hash), []byte(presented)) == 1 {
				cc.Scopes = entry.Scopes
				if entry.AgentAID != "" {
					// A token bound to a provisioned agent identity: the caller IS
					// that delegated AID, with its lineage to the owner root.
					cc.CallerAID = entry.AgentAID
					cc.DelegationChain = []string{entry.AgentAID}
					if entry.DelegatorAID != "" {
						cc.DelegationChain = append(cc.DelegationChain, entry.DelegatorAID)
					}
					// Credential-proven authority: when the agent holds a capability
					// grant (an ACDC the owner issued to it) and the KERI driver is
					// available, verify it and derive the ceiling FROM the credential
					// rather than trusting the stored scope list. A revoked, missing,
					// tampered, or wrong-issuer grant yields no scopes (default-deny).
					// Driverless builds fall back to the stored ceiling above.
					t.s.applyGrantScopes(entry, &cc)
				} else {
					cc.CallerAID = "token:" + entry.Name
				}
				return cc
			}
		}
		// An invalid token is a remote caller with no scopes — not the owner.
		return cc
	}

	// A machine this identity enrolled, signing as itself.
	//
	// This is the seam caller_resolver.go describes and left empty. The
	// enrolment ceremony already records the key a machine generated, so this
	// Identity Agent has everything it needs to recognise it again. Nothing was
	// asking.
	//
	// ASSETS, NOT CONTROLLERS. What enrolment issues is a delegated identifier,
	// which ADR-006 says a controller must never get: "A controller founds its
	// own root and is named to an owner identity derived for that machine
	// alone, exactly as a paired computer is." So this recognises the machines
	// an identity OWNS and delegated to — where a published lineage is the
	// point — and is not the controller ceremony, which is a different shape.
	//
	// IT IDENTIFIES AND GRANTS NOTHING, and that separation is the whole point
	// of doing it in this order. Scopes stay empty, so this changes what is
	// KNOWN about a caller and not one thing about what any caller may reach:
	// authorize() gives a scoped route to anyone holding any scope, so filling
	// them here would quietly hand an enrolled machine the capability surface
	// on the way past. What such a machine may do is a decision, and a separate
	// one from being able to tell who is asking.
	//
	// What it does buy immediately is an audit record that names the machine
	// and its lineage to the owner, where there was previously a remote caller
	// with no name at all.
	if a, err := t.s.identifyAssetFromSignature(r); err == nil && a != nil {
		cc.CallerAID = a.PairwiseAID
		cc.Transport = "signed"
		cc.DelegationChain = []string{a.PairwiseAID}
		if a.DelegatorAID != "" {
			cc.DelegationChain = append(cc.DelegationChain, a.DelegatorAID)
		}
		// AuthLevel and EnvelopeVerified are deliberately NOT set, and that is
		// what keeps this from granting anything.
		//
		// Both are documented to mean something stronger than a header
		// signature: EnvelopeVerified is "a valid, fresh, NON-REPLAYED
		// signed-request envelope", and this path is a header signature that
		// deliberately does not spend the replay slot. AuthLevel's
		// "signed_request" means "token + a verified per-request signature",
		// and there is no token here.
		//
		// It is not only a naming question. enrichCallerFromIdentity gives an
		// envelope-proven caller the capability ceiling of its provisioned
		// agent — so claiming an envelope here would hand an AI agent's machine
		// a set of scopes by signing a header. It happens to bail today because
		// a delegation chain is already set, which is an accident of ordering
		// in another file rather than a reason. Not claiming what we do not
		// have is the reason.
		cc.AuthLevel = "signed_headers"

		// Local stays local. Remote describes the CONNECTION — whether this
		// arrived from somewhere else — and CallerAID describes who sent it.
		// They are independent, and returning here without asking made a
		// loopback request remote purely because it identified itself.
		//
		// That cost something real: structuralAuthorizer refuses host_control
		// to any remote caller, so a host plug-in on this machine that signs
		// its requests was denied where signing nothing had been allowed. Being
		// able to say who you are should not take away standing you had for
		// being where you are.
		if isLocalOwnerRequest(r) {
			cc.Remote = false
		}
		return cc
	}

	if isLocalOwnerRequest(r) {
		cc.Remote = false
		cc.CallerAID = "local-owner"
	}
	return cc
}
