package server

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/oidc"
)

func (s *CoreServer) initOIDCHandler() error {
	if s.loginHandler == nil {
		return nil
	}
	relay := os.Getenv("IA_RELAY_URL")
	if relay == "" {
		relay = os.Getenv("IA_DEV_RELAY_URL")
	}
	if relay == "" {
		relay = "http://127.0.0.1:8765"
	}
	s.oidcAdapter = oidc.NewAdapter(s.loginHandler, relay)
	return nil
}

func (s *CoreServer) mountOIDCRoutes(r chi.Router) {
	if s.oidcAdapter == nil {
		return
	}
	r.Get("/{aid}/.well-known/openid-configuration", s.handleOIDCDiscovery)
	r.Get("/{aid}/oidc/authorize", s.handleOIDCAuthorize)
	r.Post("/{aid}/oidc/complete", s.handleOIDCComplete)
}

func (s *CoreServer) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	doc := s.oidcAdapter.DiscoveryForPairwise(aid)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

func (s *CoreServer) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	auth, err := oidc.ParseAuthRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rel, err := s.loginHandler.GetOrCreateRelationship(auth.ClientID, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bundle := auth.ToChallengeBundle(
		s.loginHandler.DevRelay+"/oobi/"+auth.ClientID,
		auth.RedirectURI,
		auth.RedirectURI,
		"oidc-"+auth.Nonce,
	)
	resp, err := s.oidcAdapter.CompleteAuthorization(auth, rel, &bundle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirect, err := oidc.BuildAuthorizationRedirect(auth, resp.IDToken, resp.VPToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (s *CoreServer) handleOIDCComplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "pending",
		"note":   "BLOCKED: cross-device SIOPv2 request_uri flow requires the relay broker",
	})
}
