package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"identity-agent-core/login"
)

// AuthRequest is a parsed OIDC/SIOPv2 authorization request mapped to SEAM-8 fields.
type AuthRequest struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	ResponseType        string
	ResponseMode        string
	State               string
	ClaimsParam         string
	VPFormat            string
	PresentationDefJSON string
	RequestedDisclosures []string
	RequestedCredentials []login.RequestedCredential
	RequestScore         *login.RequestedScore
}

// ParseAuthRequest reads standard OIDC authorization query parameters.
func ParseAuthRequest(r *http.Request) (*AuthRequest, error) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, fmt.Errorf("client_id required")
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		return nil, fmt.Errorf("redirect_uri required")
	}
	nonce := q.Get("nonce")
	if nonce == "" {
		return nil, fmt.Errorf("nonce required")
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = "openid profile email"
	}
	claimsParam := q.Get("claims")
	requestedClaims := ParseClaimsParameter(claimsParam)
	disclosures := ExpandScopes(scope, requestedClaims)

	req := &AuthRequest{
		ClientID:             clientID,
		RedirectURI:          redirectURI,
		Scope:                scope,
		Nonce:                nonce,
		ResponseType:         q.Get("response_type"),
		ResponseMode:         q.Get("response_mode"),
		State:                q.Get("state"),
		ClaimsParam:          claimsParam,
		VPFormat:             SelectVPFormat(q.Get("vp_format")),
		PresentationDefJSON:  q.Get("presentation_definition"),
		RequestedDisclosures: disclosures,
	}
	if req.ResponseType == "" {
		req.ResponseType = "id_token"
	}
	if req.ResponseMode == "" {
		req.ResponseMode = "fragment"
	}
	if q.Get("request_score") == "true" || contains(scope, "grape_score") {
		req.RequestScore = &login.RequestedScore{MinBand: "green", Required: false}
	}
	return req, nil
}

// ToChallengeBundle maps the OIDC request onto a SEAM-8 challenge bundle for consent/signing.
func (a *AuthRequest) ToChallengeBundle(siteOOBI, audience, callbackURL, sessionToken string) login.ChallengeBundle {
	return login.ChallengeBundle{
		V:                    "ASK1",
		T:                    1, // AskIntent.login
		SiteAID:              a.ClientID,
		SiteOOBI:             siteOOBI,
		Audience:             audience,
		Nonce:                a.Nonce,
		Dt:                   "",
		Expiry:               "",
		RequestedDisclosures: a.RequestedDisclosures,
		RequestedCredentials: a.RequestedCredentials,
		RequestedScore:       a.RequestScore,
		CallbackURL:          callbackURL,
		SessionToken:         sessionToken,
	}
}

// BuildAuthorizationRedirect returns the RP redirect URL with id_token (+ optional vp_token).
func BuildAuthorizationRedirect(auth *AuthRequest, idToken string, vpToken *VPToken) (string, error) {
	u, err := url.Parse(auth.RedirectURI)
	if err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("id_token", idToken)
	if vpToken != nil {
		switch vpToken.Format {
		case VPFormatSDJWT:
			params.Set("vp_token", fmt.Sprintf("%v", vpToken.Token))
		default:
			b, _ := json.Marshal(vpToken.Token)
			params.Set("vp_token", string(b))
		}
	}
	if auth.State != "" {
		params.Set("state", auth.State)
	}
	if auth.ResponseMode == "direct_post" {
		u.RawQuery = params.Encode()
		return u.String(), nil
	}
	u.Fragment = params.Encode()
	return u.String(), nil
}

func contains(scope, part string) bool {
	for _, s := range stringsFields(scope) {
		if s == part {
			return true
		}
	}
	return false
}

func stringsFields(s string) []string {
	return strings.Fields(s)
}