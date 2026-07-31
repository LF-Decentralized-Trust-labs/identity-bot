package server

import (
	"encoding/json"
	"os"
	"strconv"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/store"

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
	// Persist each delegated inception's owner-root anchoring event to the root KEL,
	// so the delegation survives a KEL reload and the delegated AID keeps verifying.
	h.PersistDelegationAnchor = s.saveDelegationAnchor
	s.assetHandler = h
	return nil
}

// saveDelegationAnchor persists a delegator (owner root) interaction event — the
// event that anchors a delegated inception in the root KEL — to the event store.
// Without this the root KEL loses the anchor on the next reload and the whole
// chain after it fails hash-chain verification.
func (s *CoreServer) saveDelegationAnchor(rootAID string, ixn map[string]interface{}) error {
	if ixn == nil {
		return nil
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return err
	}
	sn := 0
	if sStr, ok := ixn["s"].(string); ok {
		if n, perr := strconv.ParseInt(sStr, 16, 64); perr == nil {
			sn = int(n)
		}
	}
	ixnJSON, _ := json.Marshal(ixn)
	return s.DataStore.SaveEvent(store.EventRecord{
		AID:            rootAID,
		SequenceNumber: sn,
		EventType:      "ixn",
		EventJSON:      string(ixnJSON),
		PublicKey:      identity.PublicKey,
		NextKeyDigest:  identity.NextKeyDigest,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	})
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
		r.Delete("/{token}", s.assetHandler.HandleRevokeEnrolment)
	})
	r.Post("/enrol", s.assetHandler.HandleEnrol)

	// An enrolled machine asking this agent to tell somebody something. Signed
	// by the machine's own key, which is the only thing that makes it safe to
	// be reachable without being the owner.
	r.Post("/notify", s.handleAssetNotify)
}
