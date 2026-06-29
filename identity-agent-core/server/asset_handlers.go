package server

import (
	"identity-agent-core/asset"
	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) initAssetHandler() error {
	h, err := asset.NewHandler(s.DataDir, s.KeriDriver)
	if err != nil {
		return err
	}
	s.assetHandler = h
	return nil
}

func (s *CoreServer) mountAssetRoutes(r chi.Router) {
	if s.assetHandler == nil {
		return
	}
	r.Route("/assets", func(r chi.Router) {
		r.Get("/", s.assetHandler.HandleListAssets)
		r.Post("/", s.assetHandler.HandleCreateAsset)
		r.Get("/{id}", s.assetHandler.HandleGetAsset)
		r.Put("/{id}/policy", s.assetHandler.HandleUpdatePolicy)
		r.Get("/{id}/invites", s.assetHandler.HandleListInvites)
		r.Post("/{id}/invites", s.assetHandler.HandleCreateInvite)
		r.Delete("/{id}/invites/{token}", s.assetHandler.HandleRevokeInvite)
		r.Get("/{id}/requests", s.assetHandler.HandleListRequests)
		r.Post("/{id}/requests", s.assetHandler.HandleSubmitRequest)
		r.Post("/{id}/requests/{reqID}/approve", s.assetHandler.HandleApproveRequest)
		r.Post("/{id}/requests/{reqID}/deny", s.assetHandler.HandleDenyRequest)
		r.Get("/{id}/members", s.assetHandler.HandleListMembers)
		r.Delete("/{id}/members/{aid}", s.assetHandler.HandleRemoveMember)
	})
	// Public invite routes (no auth — login SDK calls these)
	r.Get("/invites/{token}", s.assetHandler.HandleGetInviteInfo)
	r.Post("/invites/{token}/redeem", s.assetHandler.HandleRedeemInvite)
}
