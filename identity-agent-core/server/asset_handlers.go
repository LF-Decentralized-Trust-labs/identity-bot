package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/internal/coretypes"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) initAssetHandler() error {
	h, err := asset.NewHandler(s.DataDir, s.KeriDriver)
	if err != nil {
		// No handler is made over a store that could not be read, and the
		// reason is kept so the asset routes can say it rather than vanish.
		s.assetHandler = nil
		s.assetStoreErr = err
		return err
	}
	s.assetStoreErr = nil
	h.VaultHas = s.isVaultEntry
	s.wireAssetHandlerHooks(h)
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
	// Persist each delegated inception's owner-root anchoring event to the root KEL,
	// so the delegation survives a KEL reload and the delegated AID keeps verifying.
	h.PersistDelegationAnchor = s.saveDelegationAnchor
	h.KeyCheck = func() error {
		switch err := s.keyCanSign(); {
		case err == nil:
			return nil
		case errors.Is(err, errKeyElsewhere):
			return asset.ErrKeyElsewhere
		default:
			return fmt.Errorf("%w: %v", asset.ErrKeyUnavailable, err)
		}
	}
	h.AskApproval = s.askApproval
	s.assetHandler = h
	return nil
}

// saveDelegationAnchor persists a delegator (owner root) interaction event — the
// event that anchors a delegated inception in the root KEL — to the event store.
// Without this the root KEL loses the anchor on the next reload and the whole
// chain after it fails hash-chain verification.
func (s *CoreServer) saveDelegationAnchor(rootAID string, approval *drivers.DriverDelegatedInceptionResponse) error {
	if approval == nil || approval.DelegatorIxn == nil {
		return nil
	}
	if err := s.saveOwnInteraction(rootAID, approval.DelegatorIxn, approval.DelegatorIxnRawBytesB64, -1, ""); err != nil {
		return err
	}
	// The approval goes to the identity's witnesses now, not on the next tick:
	// a site's approval is honoured only with their receipts, so until they
	// hold it every member would be refused.
	s.witnessOwnLog()
	return nil
}

// assetsUnavailable answers every route the asset handler would have served
// when it could not be made because a store file could not be read. It is a
// 503 naming the file, never a 404 or an empty list, and it touches nothing.
func (s *CoreServer) assetsUnavailable() http.HandlerFunc {
	err := s.assetStoreErr
	return func(w http.ResponseWriter, _ *http.Request) {
		jsonError(w, fmt.Sprintf("assets are unavailable until this is fixed: %v", err), http.StatusServiceUnavailable)
	}
}

func (s *CoreServer) mountAssetRoutes(r chi.Router) {
	if s.assetHandler == nil {
		if s.assetStoreErr != nil {
			h := s.assetsUnavailable()
			for _, p := range []string{"/assets", "/assets/*", "/invites/*", "/enrolments", "/enrolments/*", "/enrol", "/notify"} {
				r.HandleFunc(p, h)
			}
		}
		return
	}
	r.Route("/assets", func(r chi.Router) {
		r.Get("/", s.assetHandler.HandleListAssets)
		r.Post("/", s.assetHandler.HandleCreateAsset)
		r.Get("/{id}", s.assetHandler.HandleGetAsset)
		r.Put("/{id}/policy", s.assetHandler.HandleUpdatePolicy)
		r.Get("/{id}/front-ends", s.assetHandler.HandleGetFrontEnds)
		r.Put("/{id}/front-ends", s.assetHandler.HandlePutFrontEnds)
		r.Put("/{id}/front-ends/offered", s.assetHandler.HandleSetOfferedFrontEnds)
		r.Get("/{id}/app-key-grants", s.handleListAppKeyGrants)
		r.Delete("/{id}/app-key-grants/{key}", s.handleEndAppKeyGrant)
		r.Get("/{id}/invites", s.assetHandler.HandleListInvites)
		r.Post("/{id}/invites", s.assetHandler.HandleCreateInvite)
		r.Delete("/{id}/invites/{invite}", s.assetHandler.HandleRevokeInvite)
		r.Get("/{id}/requests", s.assetHandler.HandleListRequests)
		r.Post("/{id}/requests", s.assetHandler.HandleSubmitRequest)
		r.Post("/{id}/requests/{reqID}/approve", s.assetHandler.HandleApproveRequest)
		r.Post("/{id}/requests/{reqID}/deny", s.assetHandler.HandleDenyRequest)
		r.Get("/{id}/members", s.assetHandler.HandleListMembers)
		r.Delete("/{id}/members/{aid}", s.assetHandler.HandleRemoveMember)
		r.Post("/{id}/approval", s.handleAskApprovalAgain)
	})
	// Public invite routes — declared in publicRoutes, which is what actually
	// makes them reachable. The login SDK calls these from a relying party's
	// browser.
	r.Get("/invites/{token}", s.assetHandler.HandleGetInviteInfo)
	r.Post("/invites/{token}/redeem", s.assetHandler.HandleRedeemInvite)

	// Enrolling a machine that brought its own key. Issuing a token is the
	// owner's; spending it is the machine's, so only the last is public.
	r.Route("/enrolments", func(r chi.Router) {
		r.Get("/", s.assetHandler.HandleListEnrolments)
		r.Post("/", s.assetHandler.HandleCreateEnrolment)
		r.Delete("/{enrolment}", s.assetHandler.HandleRevokeEnrolment)
	})
	r.Post("/enrol", s.assetHandler.HandleEnrol)

	// An enrolled machine asking this agent to tell somebody something. Signed
	// by the machine's own key, which is the only thing that makes it safe to
	// be reachable without being the owner.
	r.Post("/notify", s.handleAssetNotify)
}

// findAgentAssetByAID returns the provisioned ai_agent asset whose delegated AID is aid.
// A nil result with a nil error means there is no such agent; an error means
// the asset store could not be read, which says nothing about whether there is.
func (s *CoreServer) lookupAgentAssetByAID(aid string) (*coretypes.AgentRef, error) {
	if s.assetHandler == nil || aid == "" {
		return nil, nil
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		if a.AssetType == "ai_agent" && a.PairwiseAID == aid && !a.ApprovalPending {
			return &coretypes.AgentRef{ID: a.ID, PairwiseAID: a.PairwiseAID, DelegatorAID: a.DelegatorAID, Capabilities: a.Capabilities}, nil
		}
	}
	return nil, nil
}

// findAgentAssetByAID is lookupAgentAssetByAID for the add-on host interface,
// which has no error to return: an unreadable store is logged and answers as
// "no such agent", which refuses rather than admits.
func (s *CoreServer) findAgentAssetByAID(aid string) *coretypes.AgentRef {
	ref, err := s.lookupAgentAssetByAID(aid)
	if err != nil {
		log.Printf("[identity-agent-core] cannot look up agent %s, the asset store is unreadable: %v", aid, err)
		return nil
	}
	return ref
}

// wireAssetHandlerHooks tells the core when the owner's decisions about an app
// must end what was granted under them.
func (s *CoreServer) wireAssetHandlerHooks(h *asset.Handler) {
	h.OnFrontEndsSwitchedOff = func(assetID string, kinds []string) {
		for _, k := range kinds {
			if _, err := s.browserKeys().EndKind(assetID, k); err != nil {
				log.Printf("[identity-agent-core] the %s keys of %s could not be ended when the owner switched them off: %v", k, assetID, err)
			}
		}
	}
	h.OnMemberRemoved = func(assetID, aid string) {
		if _, err := s.browserKeys().End(assetID, "", aid); err != nil {
			log.Printf("[identity-agent-core] the keys of a removed member of %s could not be ended: %v", assetID, err)
		}
	}
	// The delegator for per-asset delegated inception is the agent's root identity AID.
}
