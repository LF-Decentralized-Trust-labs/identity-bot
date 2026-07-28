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

func (s *CoreServer) mountSponsorRoutes(r chi.Router) {
	if s.assetHandler == nil {
		return
	}
	// Under the parent "/api" router — relative paths.
	r.Route("/sponsor", func(r chi.Router) {
		r.Post("/invites", s.handleCreateSponsorInvite)
		// Public: the sponsoring individual's agent looks up + redeems here (t=4).
		r.Get("/invites/{token}", s.assetHandler.HandleGetEmployeeInviteInfo)
		r.Post("/invites/{token}/redeem", s.handleRedeemSponsorInvite)
	})
}

// handleCreateSponsorInvite mints the org-creation sponsor invite + its signed t=4
// Ask. The sponsor relates to the org's ROOT identity (no portal exists yet during
// onboarding). The org app renders the returned URL as the sponsor QR / link.
func (s *CoreServer) handleCreateSponsorInvite(w http.ResponseWriter, r *http.Request) {
	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		publicURL = s.getPublicURL(r)
	}
	orgAID, orgOOBI, orgName := "", "", ""
	if id, _ := s.DataStore.GetIdentity(); id != nil {
		orgAID = id.AID
		orgOOBI = fmt.Sprintf("%s/public/oobi/%s", publicURL, id.AID)
	}
	if orgAID == "" {
		http.Error(w, "org identity must exist before sponsoring (create keys first)", http.StatusBadRequest)
		return
	}
	if prof, _ := s.DataStore.GetProfile(); prof != nil {
		orgName = prof.OrgName
		if orgName == "" {
			orgName = prof.FullName
		}
	}

	inv := asset.EmployeeInvite{
		Token:     genInviteToken(),
		Role:      "Super Admin",
		IsSponsor: true,
		MaxUses:   1, // a single founding sponsor
		SiteAID:   orgAID,
		SiteOOBI:  orgOOBI,
	}
	if err := s.assetHandler.Store.CreateEmployeeInvite(inv); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pwAID, pwOOBI, seed, err := s.mintPairwise("sponsor")
	if err != nil {
		http.Error(w, "mint signer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = pwAID
	ask, _ := json.Marshal(map[string]interface{}{
		"v":            "ASK1",
		"t":            4,
		"org_name":     orgName,
		"org_aid":      orgAID,
		"org_oobi":     orgOOBI,
		"site_aid":     orgAID,
		"site_oobi":    orgOOBI,
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

// handleRedeemSponsorInvite is called by the sponsoring individual's agent (t=4).
// It stores the vouch (the org's proof a real person stands behind it) and makes
// the sponsor an ACTIVE super-admin employee immediately — the founder needs no
// approval above them.
func (s *CoreServer) handleRedeemSponsorInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	var body struct {
		PairwiseAID  string `json:"pairwise_aid"`
		Name         string `json:"name"`
		OOBI         string `json:"oobi"`
		VouchSig     string `json:"vouch_sig"`
		VouchPayload string `json:"vouch_payload"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.PairwiseAID == "" || body.VouchSig == "" {
		http.Error(w, "pairwise_aid and vouch_sig required", http.StatusBadRequest)
		return
	}
	inv, ok := s.assetHandler.Store.GetEmployeeInvite(token)
	if !ok || inv.Revoked || !inv.IsSponsor {
		http.Error(w, "invalid sponsor invite", http.StatusBadRequest)
		return
	}
	if inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses {
		http.Error(w, "sponsor invite already used", http.StatusBadRequest)
		return
	}
	emp := asset.Employee{
		PairwiseAID:  body.PairwiseAID,
		Name:         body.Name,
		Role:         "Super Admin",
		Status:       "active", // founding sponsor is active immediately
		InviteToken:  token,
		OOBI:         body.OOBI,
		IsSponsor:    true,
		VouchSig:     body.VouchSig,
		VouchPayload: body.VouchPayload,
	}
	if err := s.assetHandler.Store.UpsertEmployee(emp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.assetHandler.Store.IncrementEmployeeInviteUse(token)
	scanWriteJSON(w, map[string]string{"status": "active", "role": "Super Admin"})
}
