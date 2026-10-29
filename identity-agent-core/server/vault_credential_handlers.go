package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Vault credential management: store a provider credential ONCE per service with
// its egress match domains; every capability whose egress names that service then
// uses it, injected at egress only — callers never see it. The owner, or a machine
// the owner authorised (ADR-050: storing and removing a service key is open to
// a controller). The generic LLM-key endpoint cannot set match domains,
// which left non-LLM providers (e.g. Cloudflare) uninjectable; this endpoint is
// the complete form.

type vaultCredentialRequest struct {
	Service      string            `json:"service"`
	MatchDomains []string          `json:"match_domains"`
	APIKey       string            `json:"api_key,omitempty"` // convenience: becomes Authorization: Bearer <key>
	Headers      map[string]string `json:"headers,omitempty"` // full form for non-Bearer providers
}

// handleSetVaultCredential stores/replaces one service credential in the
// encrypted vault.
func (s *CoreServer) handleSetVaultCredential(w http.ResponseWriter, r *http.Request) {
	if !s.isOwnerOrItsController(r) {
		jsonError(w, "credential management is for the owner of this agent", http.StatusForbidden)
		return
	}
	if s.Vault == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	var req vaultCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Service == "" || len(req.MatchDomains) == 0 {
		jsonError(w, "service and match_domains are required", http.StatusBadRequest)
		return
	}
	headers := req.Headers
	if len(headers) == 0 {
		if req.APIKey == "" {
			jsonError(w, "provide api_key (stored as a Bearer Authorization header) or headers", http.StatusBadRequest)
			return
		}
		headers = map[string]string{"Authorization": "Bearer " + req.APIKey}
	}
	if err := s.Vault.SetCredential(req.Service, req.MatchDomains, headers); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"saved": true, "service": req.Service, "match_domains": req.MatchDomains})
}

// handleListVaultCredentials lists configured service names only — never keys.
func (s *CoreServer) handleListVaultCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.isOwnerOrItsController(r) {
		jsonError(w, "credential management is for the owner of this agent", http.StatusForbidden)
		return
	}
	if s.Vault == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	services := s.Vault.ListServices()
	if services == nil {
		services = []string{}
	}
	jsonResponse(w, map[string]any{"services": services})
}

// handleDeleteVaultCredential removes one service credential.
func (s *CoreServer) handleDeleteVaultCredential(w http.ResponseWriter, r *http.Request) {
	if !s.isOwnerOrItsController(r) {
		jsonError(w, "credential management is for the owner of this agent", http.StatusForbidden)
		return
	}
	if s.Vault == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	service := chi.URLParam(r, "service")
	if err := s.Vault.RemoveServiceCredential(service); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"deleted": service})
}

// isVaultEntry says whether name is an entry the vault holds — a reference to
// one, not a secret, wherever a name is shown that might hold either.
func (s *CoreServer) isVaultEntry(name string) bool {
	return s.Vault != nil && s.Vault.HasService(name)
}
