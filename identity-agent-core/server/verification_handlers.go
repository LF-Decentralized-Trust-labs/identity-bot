package server

import (
	"encoding/json"
	"net/http"

	"identity-agent-core/linkverifier"
)

func (s *CoreServer) mountVerificationRoutes(r interface {
	Get(string, http.HandlerFunc)
}) {
	if s.LinkVerifier == nil {
		return
	}
	r.Get("/api/verification/badge", s.handleVerificationBadge)
}

func (s *CoreServer) handleVerificationBadge(w http.ResponseWriter, r *http.Request) {
	if !isLocalhost(r) {
		writeError(w, http.StatusForbidden, "localhost only", "loopback route")
		return
	}
	urlParam := r.URL.Query().Get("url")
	if urlParam == "" {
		writeError(w, http.StatusBadRequest, "url required", "")
		return
	}
	flow := linkverifier.Flow(r.URL.Query().Get("flow"))
	if flow == "" {
		flow = linkverifier.FlowLink
	}
	tier := linkverifier.Tier(r.URL.Query().Get("tier"))
	if tier == "" {
		tier = linkverifier.TierFree
	}
	req := linkverifier.VerifyRequest{
		Input: urlParam, Flow: flow, Tier: tier,
		InputKind: linkverifier.InputURL,
	}
	if r.URL.Query().Get("refresh") == "1" {
		req.ForceRefresh = true
	}
	result, err := s.LinkVerifier.VerifyWithContacts(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verify failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}