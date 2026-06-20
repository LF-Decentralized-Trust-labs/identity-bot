package server

import (
	"time"

	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountLoginRoutes(r chi.Router) {
	if s.loginHandler == nil {
		return
	}
	r.Route("/login", func(r chi.Router) {
		r.Post("/start", s.loginHandler.HandleStart)
		r.Post("/preview", s.loginHandler.HandlePreview)
		r.Post("/approve", s.loginHandler.HandleApprove)
		r.Post("/decline", s.loginHandler.HandleDecline)
		r.Get("/pending", s.loginHandler.HandlePendingList)
	})
}

func (s *CoreServer) initLoginHandler() error {
	h, err := login.NewHandler(s.DataDir, s.KeriDriver)
	if err != nil {
		return err
	}
	h.OnLoginPending = func(preview login.LoginPreviewResponse) {
		s.EventHub.Broadcast(AgentEvent{
			Type:      "login_pending",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Payload: map[string]interface{}{
				"session_token":         preview.SessionToken,
				"site_aid":              preview.SiteAID,
				"site_oobi":             preview.SiteOOBI,
				"audience":              preview.Audience,
				"requested_disclosures": preview.RequestedDisclosures,
				"disclosure_preview":    preview.DisclosurePreview,
				"expiry":                preview.Expiry,
				"pairwise_aid":          preview.PairwiseAID,
				"rp_session_url":        preview.RPSessionURL,
			},
		})
	}
	s.loginHandler = h
	return nil
}