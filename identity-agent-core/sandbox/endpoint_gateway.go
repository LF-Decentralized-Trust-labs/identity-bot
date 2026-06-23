package sandbox

import (
	"context"
	"fmt"
)

// Authorizer is the governance gateway's decision surface — the seam the gateway
// implements. The endpoint calls it on INGRESS (before routing a request to a plug-in)
// and on EGRESS (before returning the result), so the gateway governs both directions.
//
// Today a structural default is wired (structuralAuthorizer). When the full gateway is
// implemented it provides the real Authorizer — caller AID + ACDC-scope authorization on
// ingress, disclosure/filtering on egress — and is injected via Manager.authorizer with
// no change to the endpoint (dependency inversion; drop-in).
type Authorizer interface {
	// AuthorizeIngress returns nil to allow, or an error wrapping ErrDenied to deny.
	// (A future "hold" — request-authority/consent — is layered here too.)
	AuthorizeIngress(ctx context.Context, caller CallerContext, capDef ProvidedCapability) error
	// FilterEgress re-checks / filters a result before it leaves the agent.
	FilterEgress(ctx context.Context, caller CallerContext, capDef ProvidedCapability, res *InvokeResult) *InvokeResult
}

// structuralAuthorizer is the default Authorizer until the gateway is implemented. It
// enforces the two rules that hold regardless of per-asker policy:
//   - a host_control capability is never invocable by a remote caller, and
//   - a remote caller is default-denied without the capability in its granted scope.
//
// Egress is pass-through for now. Full per-asker ACDC-scope authorization and egress
// disclosure/filtering arrive with the gateway implementation.
type structuralAuthorizer struct{}

func (structuralAuthorizer) AuthorizeIngress(ctx context.Context, caller CallerContext, capDef ProvidedCapability) error {
	if capDef.HostControl && caller.Remote {
		return fmt.Errorf("%w: host_control capability %q is not invocable by a remote caller", ErrDenied, capDef.ID)
	}
	if caller.Remote && !containsStr(caller.Scopes, capDef.ID) {
		return fmt.Errorf("%w: caller lacks scope for capability %q", ErrDenied, capDef.ID)
	}
	return nil
}

func (structuralAuthorizer) FilterEgress(ctx context.Context, caller CallerContext, capDef ProvidedCapability, res *InvokeResult) *InvokeResult {
	// TODO(gateway): disclosure/filter rules + audit. Pass-through until implemented.
	return res
}

// authz returns the configured Authorizer, or the structural default.
func (m *Manager) authz() Authorizer {
	if m.authorizer != nil {
		return m.authorizer
	}
	return structuralAuthorizer{}
}
