package oidc

import (
	"fmt"
	"time"

	"identity-agent-core/login"
)

// Adapter bridges OIDC/SIOPv2/OIDC4VP to the native SEAM-8 login substrate.
type Adapter struct {
	Login       *login.Handler
	IssuerHost  string
	TokenTTL    time.Duration
}

// NewAdapter creates an OIDC adapter with relay-hosted issuer host (OWD-4).
func NewAdapter(h *login.Handler, issuerHost string) *Adapter {
	if h == nil {
		return nil
	}
	return &Adapter{
		Login:      h,
		IssuerHost: issuerHost,
		TokenTTL:   5 * time.Minute,
	}
}

// IssuerURL returns the per-pairwise-AID issuer base URL.
func (a *Adapter) IssuerURL(pairwiseAID string) string {
	return fmt.Sprintf("%s/%s", trimSlash(a.IssuerHost), pairwiseAID)
}

// DiscoveryForPairwise returns openid-configuration for a pairwise issuer.
func (a *Adapter) DiscoveryForPairwise(pairwiseAID string) DiscoveryDocument {
	return BuildDiscovery(a.IssuerURL(pairwiseAID))
}

// AuthorizationResponse holds OIDC authorization response artifacts.
type AuthorizationResponse struct {
	IDToken  string
	VPToken  *VPToken
	Assertion *login.Assertion
}

// CompleteAuthorization signs SEAM-8 assertion + wraps OIDC response (wrap, don't replace).
func (a *Adapter) CompleteAuthorization(
	auth *AuthRequest,
	rel *login.SiteRelationship,
	bundle *login.ChallengeBundle,
) (*AuthorizationResponse, error) {
	if a == nil || a.Login == nil {
		return nil, fmt.Errorf("adapter not configured")
	}
	var customData map[string]interface{}
	if bundle.RequestedScore != nil {
		var err error
		customData, err = a.Login.ScoreAttestation(rel)
		if err != nil {
			return nil, err
		}
	}
	assertion, err := a.Login.BuildAssertion(rel, bundle, customData)
	if err != nil {
		return nil, err
	}
	seed, err := a.Login.RelationshipSeed(rel)
	if err != nil {
		return nil, err
	}
	idToken, err := BuildIDToken(a.hostForPairwise(rel.PairwiseAID), assertion, seed, a.TokenTTL)
	if err != nil {
		return nil, err
	}
	vpToken, err := BuildVPToken(auth.VPFormat, assertion)
	if err != nil {
		return nil, err
	}
	return &AuthorizationResponse{
		IDToken:   idToken,
		VPToken:   vpToken,
		Assertion: assertion,
	}, nil
}

func (a *Adapter) hostForPairwise(pairwiseAID string) string {
	// Issuer host is relay base; pairwise path is in the did:webs identifier.
	return trimSlash(a.IssuerHost)
}