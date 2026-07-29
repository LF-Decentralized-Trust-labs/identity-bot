package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/sandbox"
)

// The access model — who may invoke a capability at this endpoint.
//
// This is the WHO gate, orthogonal to (and composed with) the capability grant,
// which is the WHAT gate: the grant fixes the ceiling of actions an agent may take,
// the access policy fixes which callers are allowed to reach a capability at all.
//
// It is identity-first: the primary credential is the caller's AID, proven either by
// a signed-request envelope (strongest) or by a bearer token bound to a provisioned
// agent identity (medium). A bare, anonymous bearer token is the weakest rung and is
// admitted only under the explicit open_token mode. Owners opt IN to token access; a
// bare token is off by default.
//
// Four modes:
//   - same_owner          — only identities delegated from this owner root (the default)
//   - specific_identities — an explicit allowlist of caller AIDs
//   - by_credential       — any caller holding a valid ACDC of a named schema/issuer
//   - open_token          — open to anyone presenting a valid bearer token
type AccessMode string

const (
	AccessSameOwner          AccessMode = "same_owner"
	AccessSpecificIdentities AccessMode = "specific_identities"
	AccessByCredential       AccessMode = "by_credential"
	AccessOpenToken          AccessMode = "open_token"
)

// AccessPolicy is the owner-set rule governing who may invoke one capability.
type AccessPolicy struct {
	Mode AccessMode `json:"mode"`
	// AllowedAIDs is the allowlist for specific_identities.
	AllowedAIDs []string `json:"allowed_aids,omitempty"`
	// RequiredCredSchema / RequiredCredIssuer gate by_credential: the caller must hold
	// a valid, unrevoked ACDC of this schema (and, if set, from this issuer AID).
	RequiredCredSchema string `json:"required_cred_schema,omitempty"`
	RequiredCredIssuer string `json:"required_cred_issuer,omitempty"`
	// TokenAllowed decides whether a bearer token bound to a provisioned agent is
	// accepted as sufficient identity proof for the identity modes (same_owner,
	// specific_identities, by_credential), or whether a freshly signed request
	// envelope is required. It has no effect on open_token (which is token access by
	// definition). Default true preserves the agent-bound-token flow; set false to
	// demand a per-request signature. It is NOT what opens anonymous token access —
	// that is the open_token mode.
	TokenAllowed bool `json:"token_allowed"`
}

// builtinDefaultAccessPolicy is the fallback for a capability with no explicit policy
// and no "*" override: same-owner only, admitting an agent-bound token. Anonymous
// (chain-less) tokens fail this — token access to outside callers is opt-in via
// open_token. This is the safe, private default: an agent delegated from this owner
// can invoke; nobody else can.
func builtinDefaultAccessPolicy() AccessPolicy {
	return AccessPolicy{Mode: AccessSameOwner, TokenAllowed: true}
}

const accessPolicyDefaultKey = "*"

var accessPolicyMu sync.Mutex

func (s *CoreServer) accessPolicyPath() string {
	return filepath.Join(s.DataDir, "access_policy.json")
}

func (s *CoreServer) loadAccessPolicies() map[string]AccessPolicy {
	data, err := os.ReadFile(s.accessPolicyPath())
	if err != nil {
		return map[string]AccessPolicy{}
	}
	var m map[string]AccessPolicy
	if json.Unmarshal(data, &m) != nil || m == nil {
		return map[string]AccessPolicy{}
	}
	return m
}

func (s *CoreServer) saveAccessPolicies(m map[string]AccessPolicy) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.accessPolicyPath(), data, 0600)
}

// accessPolicyFor returns the effective policy for a capability: its own entry, else
// the "*" override, else the built-in default.
func (s *CoreServer) accessPolicyFor(capabilityID string) AccessPolicy {
	accessPolicyMu.Lock()
	m := s.loadAccessPolicies()
	accessPolicyMu.Unlock()
	if p, ok := m[capabilityID]; ok {
		return p
	}
	if p, ok := m[accessPolicyDefaultKey]; ok {
		return p
	}
	return builtinDefaultAccessPolicy()
}

// validateAccessPolicy checks a policy is internally coherent for its mode.
func validateAccessPolicy(p AccessPolicy) string {
	switch p.Mode {
	case AccessSameOwner, AccessOpenToken:
		return ""
	case AccessSpecificIdentities:
		if len(p.AllowedAIDs) == 0 {
			return "specific_identities requires a non-empty allowed_aids list"
		}
		return ""
	case AccessByCredential:
		if p.RequiredCredSchema == "" {
			return "by_credential requires required_cred_schema"
		}
		return ""
	default:
		return "unknown access mode " + string(p.Mode)
	}
}

// handleGetAccessPolicies returns every set policy plus the effective default. Local
// owner only — access policy is the owner's to read and set.
func (s *CoreServer) handleGetAccessPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "access policy is local-owner only", http.StatusForbidden)
		return
	}
	accessPolicyMu.Lock()
	m := s.loadAccessPolicies()
	accessPolicyMu.Unlock()
	def := builtinDefaultAccessPolicy()
	if p, ok := m[accessPolicyDefaultKey]; ok {
		def = p
	}
	jsonResponse(w, map[string]any{
		"policies": m,   // keyed by capability id; "*" is the owner-set default override
		"default":  def, // the effective default for capabilities with no explicit entry
		"modes":    []AccessMode{AccessSameOwner, AccessSpecificIdentities, AccessByCredential, AccessOpenToken},
	})
}

// handleSetAccessPolicy sets the policy for one capability (or, with capability
// "default", the "*" override). Local owner only.
func (s *CoreServer) handleSetAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "access policy is local-owner only", http.StatusForbidden)
		return
	}
	key := chi.URLParam(r, "capability")
	if key == "default" {
		key = accessPolicyDefaultKey
	}
	if key == "" {
		jsonError(w, "capability is required", http.StatusBadRequest)
		return
	}
	var p AccessPolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, "invalid policy body", http.StatusBadRequest)
		return
	}
	if msg := validateAccessPolicy(p); msg != "" {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	accessPolicyMu.Lock()
	defer accessPolicyMu.Unlock()
	m := s.loadAccessPolicies()
	m[key] = p
	if err := s.saveAccessPolicies(m); err != nil {
		jsonError(w, "failed to persist policy", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"capability": key, "policy": p})
}

// handleDeleteAccessPolicy removes a capability's explicit policy, reverting it to the
// default. Local owner only.
func (s *CoreServer) handleDeleteAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "access policy is local-owner only", http.StatusForbidden)
		return
	}
	key := chi.URLParam(r, "capability")
	if key == "default" {
		key = accessPolicyDefaultKey
	}
	accessPolicyMu.Lock()
	defer accessPolicyMu.Unlock()
	m := s.loadAccessPolicies()
	if _, ok := m[key]; !ok {
		jsonError(w, "no policy set for that capability", http.StatusNotFound)
		return
	}
	delete(m, key)
	if err := s.saveAccessPolicies(m); err != nil {
		jsonError(w, "failed to persist policy", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"capability": key, "reverted_to_default": true})
}

// evaluateAccessPolicy is the pure WHO decision: does this caller satisfy this policy?
// It returns "" to allow or a plain-language denial reason. It never consults storage —
// ownerRoot and holdsCred are supplied by the caller so this stays unit-testable.
//
//   - identityProven means we know WHO the caller is: a verified signed-request
//     envelope, or (when the policy admits it) a token bound to a provisioned agent
//     identity carrying a real AID + delegation chain. A bare anonymous token is never
//     identity-proven.
func evaluateAccessPolicy(p AccessPolicy, caller sandbox.CallerContext, ownerRoot string, holdsCred func(schema, issuer string) bool) string {
	hasResolvedAID := caller.CallerAID != "" && len(caller.DelegationChain) > 0
	identityProven := caller.EnvelopeVerified || (p.TokenAllowed && hasResolvedAID)

	switch p.Mode {
	case AccessOpenToken:
		// The permissive mode: any authenticated caller (already scope-gated) is in.
		if caller.CallerAID == "" {
			return "authentication required"
		}
		return ""
	case AccessSameOwner:
		if !identityProven {
			return "this capability requires a proven same-owner identity (sign the request, or enable token access)"
		}
		if ownerRoot == "" || !containsString(caller.DelegationChain, ownerRoot) {
			return "caller is not an identity delegated from this owner"
		}
		return ""
	case AccessSpecificIdentities:
		if !identityProven {
			return "this capability requires a proven caller identity"
		}
		if !containsString(p.AllowedAIDs, caller.CallerAID) {
			return "caller identity is not on this capability's allowlist"
		}
		return ""
	case AccessByCredential:
		if !identityProven {
			return "this capability requires a proven caller identity"
		}
		if holdsCred == nil || !holdsCred(p.RequiredCredSchema, p.RequiredCredIssuer) {
			return "caller does not hold the credential this capability requires"
		}
		return ""
	default:
		return "unknown access mode"
	}
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
