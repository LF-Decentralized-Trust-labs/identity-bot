package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"identity-agent-core/asset"
	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountEmployeeRoutes(r chi.Router) {
	if s.assetHandler == nil {
		return
	}
	// Mounted under the parent "/api" router, so paths here are relative.
	r.Route("/employees", func(r chi.Router) {
		r.Get("/", s.assetHandler.HandleListEmployees)
		r.Get("/invites", s.assetHandler.HandleListEmployeeInvites)
		r.Post("/invites", s.handleCreateEmployeeInvite)
		r.Delete("/invites/{token}", s.assetHandler.HandleRevokeEmployeeInvite)
		// Public: the accepting employee's agent looks up + redeems here during add_employee (t=3).
		r.Get("/invites/{token}", s.assetHandler.HandleGetEmployeeInviteInfo)
		r.Post("/invites/{token}/redeem", s.handleRedeemEmployeeInvite)
		r.Post("/{aid}/approve", s.handleApproveEmployee)
		r.Post("/{aid}/revoke", s.handleRevokeEmployee)
	})
}

// handleCreateEmployeeInvite mints an employee invite AND its signed t=3 Ask, hosted
// at /i/{token} so the org can share it as a QR / link. `asset_id` names the portal the
// employment grants access to; the accepting employee derives their stable pairwise AID
// against that portal so it matches their later login.
func (s *CoreServer) handleCreateEmployeeInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Role    string `json:"role"`
		Label   string `json:"label"`
		MaxUses int    `json:"max_uses"`
		AssetID string `json:"asset_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		publicURL = s.getPublicURL(r)
	}

	// Resolve the target portal (asset) → its SiteAID + OOBI.
	siteAID, siteOOBI := "", ""
	if body.AssetID != "" {
		if a, ok := s.assetHandler.Store.GetAsset(body.AssetID); ok {
			siteAID = a.PairwiseAID
			siteOOBI = fmt.Sprintf("%s/public/oobi/%s", publicURL, a.PairwiseAID)
		}
	}
	if siteAID == "" {
		http.Error(w, "asset_id must name an existing portal asset", http.StatusBadRequest)
		return
	}

	inv := asset.EmployeeInvite{
		Token:    genInviteToken(),
		Role:     body.Role,
		Label:    body.Label,
		MaxUses:  body.MaxUses,
		AssetID:  body.AssetID,
		SiteAID:  siteAID,
		SiteOOBI: siteOOBI,
	}
	if err := s.assetHandler.Store.CreateEmployeeInvite(inv); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Org identity for the Ask payload (a known public entity — no unlinkability need).
	orgAID, orgOOBI, orgName := "", "", ""
	if id, _ := s.DataStore.GetIdentity(); id != nil {
		orgAID = id.AID
		orgOOBI = fmt.Sprintf("%s/public/oobi/%s", publicURL, id.AID)
	}
	if prof, _ := s.DataStore.GetProfile(); prof != nil {
		orgName = prof.FullName
	}

	// Sign the Ask with a minted pairwise (base-layer signature the accepter verifies).
	pwAID, pwOOBI, seed, err := s.mintPairwise("addemployee")
	if err != nil {
		http.Error(w, "mint signer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = pwAID
	ask, _ := json.Marshal(map[string]interface{}{
		"v":            "ASK1",
		"t":            3,
		"org_name":     orgName,
		"org_aid":      orgAID,
		"org_oobi":     orgOOBI,
		"site_aid":     siteAID,
		"site_oobi":    siteOOBI,
		"role":         body.Role,
		"invite_token": inv.Token,
		"signer_oobi":  pwOOBI,
	})
	sig, serr := login.SignAsk(ask, seed)
	if serr != nil {
		http.Error(w, "sign ask: "+serr.Error(), http.StatusInternalServerError)
		return
	}
	if signed, ierr := injectSig(ask, sig); ierr == nil {
		ask = signed
	}
	tb := make([]byte, 16)
	_, _ = rand.Read(tb)
	askToken := hex.EncodeToString(tb)
	mintedAsks.Lock()
	mintedAsks.m[askToken] = ask
	mintedAsks.Unlock()

	scanWriteJSON(w, map[string]interface{}{
		"invite": inv,
		"token":  askToken,
		"url":    fmt.Sprintf("%s/i/%s", publicURL, askToken),
	})
}

// handleRedeemEmployeeInvite is called by the accepting employee's agent during
// add_employee. It records them on the roster as PENDING (the org must approve before
// the membership gate admits them).
func (s *CoreServer) handleRedeemEmployeeInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	var body struct {
		PairwiseAID string `json:"pairwise_aid"`
		Name        string `json:"name"`
		OOBI        string `json:"oobi"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.PairwiseAID == "" {
		http.Error(w, "pairwise_aid required", http.StatusBadRequest)
		return
	}
	inv, ok := s.assetHandler.Store.GetEmployeeInvite(token)
	if !ok || inv.Revoked {
		http.Error(w, "invalid invite", http.StatusBadRequest)
		return
	}
	if inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses {
		http.Error(w, "invite exhausted", http.StatusBadRequest)
		return
	}
	emp := asset.Employee{
		PairwiseAID: body.PairwiseAID,
		Name:        body.Name,
		Role:        inv.Role,
		Status:      "pending",
		InviteToken: token,
		OOBI:        body.OOBI,
	}
	if err := s.assetHandler.Store.UpsertEmployee(emp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.assetHandler.Store.IncrementEmployeeInviteUse(token)
	scanWriteJSON(w, map[string]string{"status": "pending"})
}

func (s *CoreServer) handleApproveEmployee(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	emp, ok, err := s.assetHandler.Store.SetEmployeeStatus(aid, "active", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "employee not found", http.StatusNotFound)
		return
	}
	scanWriteJSON(w, emp)
}

func (s *CoreServer) handleRevokeEmployee(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	emp, ok, err := s.assetHandler.Store.SetEmployeeStatus(aid, "revoked", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "employee not found", http.StatusNotFound)
		return
	}
	scanWriteJSON(w, emp)
}

func genInviteToken() string {
	tb := make([]byte, 16)
	_, _ = rand.Read(tb)
	return hex.EncodeToString(tb)
}
