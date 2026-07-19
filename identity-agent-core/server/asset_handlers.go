package server

import (
	"os"

	"identity-agent-core/asset"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) initAssetHandler() error {
	h, err := asset.NewHandler(s.DataDir, s.KeriDriver)
	if err != nil {
		return err
	}
	// The delegator for per-asset delegated inception is the agent's root identity AID.
	h.RootAID = func() string {
		if id, _ := s.DataStore.GetIdentity(); id != nil {
			return id.AID
		}
		return ""
	}
	// Configured default delegation model for new assets when the request omits one. Org
	// deployments set ASSET_DEFAULT_DELEGATION_MODEL=delegated (per-asset AIDs anchor to the
	// org root); individuals leave it unset and get standalone AIDs. An explicit request field
	// still overrides this. Reads an env var today; swap for a stored per-agent setting later
	// without touching the asset handler.
	h.DefaultDelegationModel = func() string {
		return os.Getenv("ASSET_DEFAULT_DELEGATION_MODEL")
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
