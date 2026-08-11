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
//
// These seams are opt-in: an overlay that registers nothing simply gets core
// behaviour. There is one that is NOT optional and therefore does not live
// here — identity-agent-core/volume.Handle, which an overlay must call before
// starting its server. It sits outside this file because it runs before a
// server exists, and an overlay that skips it produces an instance whose data
// volume is never encrypted. Named here so this file remains a complete index
// of what an overlay has to think about.

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

// MemberInfoResolver is an OPTIONAL companion interface a MembershipResolver
// may also implement to describe an admitted member — e.g. {"role": "Editor",
// "display_name": "Ada"}. When present, the info rides the login result to the
// relying party, so the RP never needs to query org-internal rosters: the
// membership source that admitted the identity is also the authority on who it
// admitted.
type MemberInfoResolver interface {
	MemberInfo(pairwiseAID, assetID string) (info map[string]string, ok bool)
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
// overlay can add its own endpoints.
func (s *CoreServer) MountExtraRoutes(fn func(chi.Router)) {
	s.extraRoutes = append(s.extraRoutes, fn)
}

// StoreAsk registers a pre-built, signed Ask under token so the core serves it at
// the canonical /i/{token} URL — the same fetch path every scanner already uses
// for core-minted Asks. An overlay that originates its own Asks (e.g. a QR a
// counterpart agent mints for someone to scan) calls this instead of hosting a
// separate route, so its Asks are indistinguishable to scanners from core ones.
func StoreAsk(token string, ask []byte) {
	mintedAsks.Lock()
	mintedAsks.m[token] = ask
	mintedAsks.Unlock()
}
