package oidc

import (
	"encoding/json"
	"strings"
)

const ClaimNamespace = "https://identityagent.org/claims"

// ScopeAliases expand coarse OIDC scopes into explicit login-contract disclosure fields.
var ScopeAliases = map[string][]string{
	"openid":  {},
	"profile": {"display_name"},
	"email":   {"email"},
}

// DisclosureToClaim maps login-contract disclosure field names to OIDC claim names.
var DisclosureToClaim = map[string]string{
	"display_name": "name",
	"email":        "email",
}

// ClaimToDisclosure inverts the standard OIDC claim mapping.
var ClaimToDisclosure = map[string]string{
	"name":  "display_name",
	"email": "email",
}

// ExpandScopes returns deduplicated login-contract disclosure fields for scope + claims request.
func ExpandScopes(scope string, requestedClaims []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(f string) {
		if f == "" || seen[f] {
			return
		}
		seen[f] = true
		out = append(out, f)
	}
	for _, part := range strings.Fields(scope) {
		for _, f := range ScopeAliases[part] {
			add(f)
		}
	}
	for _, c := range requestedClaims {
		if d, ok := ClaimToDisclosure[c]; ok {
			add(d)
			continue
		}
		if strings.HasPrefix(c, ClaimNamespace+"/") {
			add(strings.TrimPrefix(c, ClaimNamespace+"/"))
		}
	}
	return out
}

// ClaimsFromDisclosures maps granted login-contract disclosures to OIDC ID token claims.
func ClaimsFromDisclosures(disclosures map[string]string) map[string]interface{} {
	claims := map[string]interface{}{}
	for field, value := range disclosures {
		if claim, ok := DisclosureToClaim[field]; ok {
			claims[claim] = value
			continue
		}
		claims[ClaimNamespace+"/"+field] = value
	}
	return claims
}

// ParseClaimsParameter extracts claim names from an OIDC claims JSON request (dev subset).
func ParseClaimsParameter(raw string) []string {
	if raw == "" {
		return nil
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil
	}
	var names []string
	if idToken, ok := doc["id_token"].(map[string]interface{}); ok {
		for k := range idToken {
			names = append(names, k)
		}
	}
	if userInfo, ok := doc["userinfo"].(map[string]interface{}); ok {
		for k := range userInfo {
			names = append(names, k)
		}
	}
	return names
}
