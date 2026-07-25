package asset

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

type Handler struct {
	Store      *Store
	KeriDriver *drivers.KeriDriver
	dataDir    string

	// RootAID returns the AID of the agent's root identity (the delegator for per-asset
	// delegated inception), or "" if no root identity exists yet. Injected by the server so
	// this package stays free of the identity store. Nil is treated as "".
	RootAID func() string

	// DefaultDelegationModel returns the agent's configured default delegation model for new
	// assets when the request doesn't specify one: "delegated" | "standalone" | "" (unset).
	// This is the flexibility seam: an org deployment configures "delegated" (per-asset AIDs
	// anchor to the org root — provable ownership); an individual leaves it standalone (no
	// forced root<->asset correlation). An explicit request field always overrides this, and
	// the resolver can later read a stored per-agent setting instead of an env var without
	// touching this handler. Nil / "" falls through to the neutral built-in default.
	DefaultDelegationModel func() string

	// PersistDelegationAnchor persists the delegator's (owner root's) anchoring interaction
	// event to the root KEL after a delegated inception. Injected by the server so this
	// package stays free of the identity/event store. It is MANDATORY for delegated assets:
	// without it, the anchor is lost on the next KEL reload and delegation verification
	// breaks (the root KEL develops a sequence gap). Nil is only acceptable where no
	// delegated inception occurs (standalone assets / tests).
	PersistDelegationAnchor func(rootAID string, delegatorIxn map[string]interface{}) error
}

func NewHandler(dataDir string, keri *drivers.KeriDriver) (*Handler, error) {
	st, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &Handler{Store: st, KeriDriver: keri, dataDir: dataDir}, nil
}

// persistDelegationAnchor saves the root's anchoring interaction event for a
// delegated inception. A missing DelegatorIxn or an unwired callback is a hard
// error for a delegated asset — silently skipping it is precisely what produced
// the root-KEL sequence gap that broke delegation verification.
func (h *Handler) persistDelegationAnchor(rootAID string, delegatorIxn map[string]interface{}) error {
	if delegatorIxn == nil {
		return fmt.Errorf("driver returned no delegator anchoring event")
	}
	if h.PersistDelegationAnchor == nil {
		return fmt.Errorf("no delegation-anchor persistence configured")
	}
	return h.PersistDelegationAnchor(rootAID, delegatorIxn)
}

func (h *Handler) writeJSON(w http.ResponseWriter, v interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) HandleListAssets(w http.ResponseWriter, r *http.Request) {
	assets := h.Store.ListAssets()
	type item struct {
		Asset        Asset `json:"asset"`
		MemberCount  int   `json:"member_count"`
		PendingCount int   `json:"pending_count"`
	}
	var out []item
	for _, a := range assets {
		mems := h.Store.ListMembers(a.ID)
		reqs := h.Store.ListRequests(a.ID)
		pending := 0
		for _, rq := range reqs {
			if rq.Status == "pending" {
				pending++
			}
		}
		out = append(out, item{Asset: a, MemberCount: len(mems), PendingCount: pending})
	}
	h.writeJSON(w, map[string]interface{}{"assets": out}, http.StatusOK)
}

func (h *Handler) HandleCreateAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisplayName     string           `json:"display_name"`
		Origin          string           `json:"origin"`
		AssetType       string           `json:"asset_type"`
		DelegationModel string           `json:"delegation_model"`
		Policy          EnrollmentPolicy `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeJSON(w, map[string]string{"error": "bad request"}, http.StatusBadRequest)
		return
	}
	if body.DisplayName == "" || body.Origin == "" || body.AssetType == "" {
		h.writeJSON(w, map[string]string{"error": "missing fields"}, http.StatusBadRequest)
		return
	}

	// Derive the asset's signing keypair from the controller root seed (HD), keyed by a
	// stable per-asset index. The private seed is never stored — re-derived on demand
	// (root + SigningIndex) so the agent can sign challenges on behalf of this asset.
	// (Previously the keypair was random and the private half discarded, so the asset
	// could never sign at all.)
	id := genID()
	signingIndex := signingIndexForID(id)
	pub, nextPub, derr := deriveAssetKeypair(h.dataDir, signingIndex)
	if derr != nil {
		h.writeJSON(w, map[string]string{"error": "derive asset key: " + derr.Error()}, http.StatusInternalServerError)
		return
	}
	pubB64 := iacrypto.VerkeyQB64(pub)
	nextB64 := iacrypto.VerkeyQB64(nextPub)

	// Resolve the delegation model with an explicit precedence, so the org-vs-individual choice
	// is a policy — not baked into the code:
	//   1. an explicit request field always wins ("delegated" | "standalone");
	//   2. otherwise the agent's configured default (org deployments set "delegated");
	//   3. otherwise a neutral built-in default of "standalone" (an individual gets an
	//      unlinked per-asset AID unless something opts into delegation).
	// A delegated AID anchors back to the root AID (the driver keys identities by AID, so the
	// root AID IS the delegator name), which is what an org wants for provable ownership.
	rootAID := ""
	if h.RootAID != nil {
		rootAID = h.RootAID()
	}
	requested := body.DelegationModel
	model := requested
	if model == "" && h.DefaultDelegationModel != nil {
		model = h.DefaultDelegationModel()
	}
	if model == "" {
		model = "standalone"
	}
	// Delegation needs a root identity to delegate from. If the caller explicitly asked for it
	// without one, that's an error; if it was only the default, degrade gracefully to standalone
	// rather than failing asset creation.
	if model == "delegated" && rootAID == "" {
		if requested == "delegated" {
			h.writeJSON(w, map[string]string{"error": "delegated inception requires a root identity"}, http.StatusBadRequest)
			return
		}
		model = "standalone"
	}

	var pairwise string
	var delegator string

	if model == "delegated" {
		resp, err := h.KeriDriver.CreateDelegatedInception(pubB64, nextB64, body.DisplayName, rootAID)
		if err != nil {
			h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
			return
		}
		// Persist the root's anchoring event, or the delegation won't survive a KEL
		// reload. Fail creation rather than mint a delegated asset that can't verify.
		if err := h.persistDelegationAnchor(rootAID, resp.DelegatorIxn); err != nil {
			h.writeJSON(w, map[string]string{"error": "persist delegation anchor: " + err.Error()}, http.StatusInternalServerError)
			return
		}
		pairwise = resp.AID
		delegator = resp.DelegatorAID
	} else {
		resp, err := h.KeriDriver.CreateInceptionNamed(pubB64, nextB64, body.DisplayName)
		if err != nil {
			h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
			return
		}
		pairwise = resp.AID
	}

	asset := Asset{
		ID:              id,
		DisplayName:     body.DisplayName,
		AssetType:       body.AssetType,
		Origin:          body.Origin,
		PairwiseAID:     pairwise,
		DelegationModel: model,
		DelegatorAID:    delegator,
		Policy:          body.Policy,
		SigningIndex:    signingIndex,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	h.Store.UpsertAsset(asset)

	sdk := map[string]string{
		"SITE_PAIRWISE_AID": asset.PairwiseAID,
		"SITE_OOBI":         fmt.Sprintf("http://127.0.0.1:5050/public/oobi/%s", asset.PairwiseAID),
		"ASSET_ID":          asset.ID,
		"ENROLLMENT_MODE":   string(asset.Policy.Mode),
	}

	h.writeJSON(w, map[string]interface{}{"asset": asset, "sdk_config": sdk}, http.StatusCreated)
}

func (h *Handler) HandleGetAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, ok := h.Store.GetAsset(id)
	if !ok {
		h.writeJSON(w, map[string]string{"error": "not found"}, http.StatusNotFound)
		return
	}
	sdk := map[string]string{
		"SITE_PAIRWISE_AID": a.PairwiseAID,
		"SITE_OOBI":         fmt.Sprintf("http://127.0.0.1:5050/public/oobi/%s", a.PairwiseAID),
		"ASSET_ID":          a.ID,
		"ENROLLMENT_MODE":   string(a.Policy.Mode),
	}
	h.writeJSON(w, map[string]interface{}{"asset": a, "sdk_config": sdk}, http.StatusOK)
}

func (h *Handler) HandleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var pol EnrollmentPolicy
	json.NewDecoder(r.Body).Decode(&pol)
	a, ok := h.Store.GetAsset(id)
	if !ok {
		h.writeJSON(w, map[string]string{"error": "not found"}, http.StatusNotFound)
		return
	}
	a.Policy = pol
	a.UpdatedAt = time.Now().UTC()
	h.Store.UpsertAsset(a)
	h.writeJSON(w, a, http.StatusOK)
}

func (h *Handler) HandleCreateInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Label   string `json:"label"`
		MaxUses int    `json:"max_uses"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.MaxUses == 0 {
		body.MaxUses = 0 // unlimited
	}
	token := genToken()
	inv := AssetInvite{
		Token:     token,
		AssetID:   id,
		Label:     body.Label,
		MaxUses:   body.MaxUses,
		UseCount:  0,
		CreatedAt: time.Now().UTC(),
	}
	h.Store.CreateInvite(inv)
	h.writeJSON(w, inv, http.StatusCreated)
}

func (h *Handler) HandleListInvites(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.writeJSON(w, h.Store.ListInvites(id), http.StatusOK)
}

func (h *Handler) HandleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	h.Store.RevokeInvite(token)
	h.writeJSON(w, map[string]bool{"revoked": true}, http.StatusOK)
}

func (h *Handler) HandleGetInviteInfo(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	inv, ok := h.Store.GetInvite(token)
	if !ok || inv.Revoked {
		h.writeJSON(w, map[string]string{"error": "invalid"}, http.StatusNotFound)
		return
	}
	h.writeJSON(w, inv, http.StatusOK)
}

func (h *Handler) HandleRedeemInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	// TODO: enforce policy.RequiredAAL >= asset.Policy.RequiredAAL before granting membership.
	inv, ok := h.Store.GetInvite(token)
	if !ok || inv.Revoked {
		h.writeJSON(w, map[string]string{"error": "invalid"}, http.StatusBadRequest)
		return
	}
	// create member stub (pairwise from login context later)
	h.Store.IncrementInviteUse(token)
	h.writeJSON(w, map[string]string{"status": "redeemed"}, http.StatusOK)
}

func (h *Handler) HandleListRequests(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.writeJSON(w, h.Store.ListRequests(id), http.StatusOK)
}

func (h *Handler) HandleSubmitRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		RequesterInfo map[string]string `json:"requester_info"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	req := AssetAccessRequest{
		ID:            genID(),
		AssetID:       id,
		RequesterInfo: body.RequesterInfo,
		Status:        "pending",
		CreatedAt:     time.Now().UTC(),
	}
	h.Store.CreateRequest(req)
	h.writeJSON(w, req, http.StatusCreated)
}

func (h *Handler) HandleApproveRequest(w http.ResponseWriter, r *http.Request) {
	reqID := chi.URLParam(r, "reqID")
	// TODO: enforce policy.RequiredAAL
	h.Store.UpdateRequestStatus(reqID, "approved")
	h.writeJSON(w, map[string]string{"status": "approved"}, http.StatusOK)
}

func (h *Handler) HandleDenyRequest(w http.ResponseWriter, r *http.Request) {
	reqID := chi.URLParam(r, "reqID")
	h.Store.UpdateRequestStatus(reqID, "denied")
	h.writeJSON(w, map[string]string{"status": "denied"}, http.StatusOK)
}

func (h *Handler) HandleListMembers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.writeJSON(w, h.Store.ListMembers(id), http.StatusOK)
}

func (h *Handler) HandleRemoveMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	aid := chi.URLParam(r, "aid")
	h.Store.RemoveMember(id, aid)
	h.writeJSON(w, map[string]bool{"removed": true}, http.StatusOK)
}

func genID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func genToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
