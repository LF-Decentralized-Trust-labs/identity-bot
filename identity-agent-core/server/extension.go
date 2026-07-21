package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
)

// This file is the core's OVERLAY EXTENSION SURFACE. It carries no business
// logic of its own — it defines the seams an overlay (or a third-party agent)
// uses to add its side of an action without forking core: a membership-gate
// resolver registry, a router-mount hook, and a couple of read/mint accessors.
// The core ships no overlays; these are inert until something registers.

// MembershipResolver decides whether a pairwise AID is admitted to an asset
// whose EnrollmentPolicy.MembershipSource names this resolver. This is how an
// org agent gates login on its own roster — e.g. an "employees" resolver that
// admits only active employees — while the interoperability contract (present an
// anchored pairwise, the challenge/response) stays in core.
type MembershipResolver interface {
	// Admit reports whether pairwiseAID may access assetID; reason is a
	// human-readable denial message when ok is false.
	Admit(pairwiseAID, assetID string) (ok bool, reason string)
}

var membershipResolvers = map[string]MembershipResolver{}

// RegisterMembershipResolver registers r as the resolver for policies whose
// MembershipSource == source (e.g. "employees"). Call during startup, before
// serving; not safe for concurrent registration.
func RegisterMembershipResolver(source string, r MembershipResolver) {
	membershipResolvers[source] = r
}

func membershipResolverFor(source string) MembershipResolver {
	return membershipResolvers[source]
}

// AssetStore returns the core asset store (assets + members). Overlays read it to
// resolve site AIDs / assets; they keep their own stores for org-specific rosters.
func (s *CoreServer) AssetStore() *asset.Store {
	if s.assetHandler == nil {
		return nil
	}
	return s.assetHandler.Store
}

// MintPairwise mints a fresh pairwise AID (aid, oobi, seed). Overlays use it to
// establish org-scoped relationships during their own ceremonies.
func (s *CoreServer) MintPairwise(name string) (aid, oobi string, seed []byte, err error) {
	return s.mintPairwise(name)
}

// PublicURL resolves the agent's externally reachable base URL for a request —
// overlays use it to build OOBIs / redeem URLs in their responses.
func (s *CoreServer) PublicURL(r *http.Request) string {
	return s.getPublicURL(r)
}

// MountExtraRoutes registers fn to add routes under the core's /api router. Call
// during startup, before serving; fn runs inside the /api chi.Route group, so an
// overlay can add e.g. POST /api/employees/invites/{token}/redeem.
func (s *CoreServer) MountExtraRoutes(fn func(chi.Router)) {
	s.extraRoutes = append(s.extraRoutes, fn)
}
