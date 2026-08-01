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

func (s *CoreServer) mountSignerRoutes(r chi.Router) {
	if s.assetHandler == nil {
		return
	}
	// Under the parent "/api" router — relative paths.
	r.Route("/signer", func(r chi.Router) {
		r.Post("/invites", s.handleCreateSignerInvite)
		// Public: the signing individual's agent looks up + redeems here (t=4).
		r.Get("/invites/{token}", s.assetHandler.HandleGetEmployeeInviteInfo)
		r.Post("/invites/{token}/redeem", s.handleRedeemSignerInvite)
	})
}

// handleCreateSignerInvite mints the founding-signer invite and its signed t=4
// Ask. The signer relates to the organisation's ROOT identity — no portal exists
// yet during onboarding. The organisation's app renders the returned URL as the
// QR or link a founding signer scans.
func (s *CoreServer) handleCreateSignerInvite(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "the organisation's identity must exist before it can be signed for (create keys first)", http.StatusBadRequest)
		return
	}
	if prof, _ := s.DataStore.GetProfile(); prof != nil {
		orgName = prof.OrgName
		if orgName == "" {
			orgName = prof.FullName
		}
	}

	inv := asset.EmployeeInvite{
		Token:    genInviteToken(),
		Role:     "Super Admin",
		IsSigner: true,
		MaxUses:  1, // a single founding signer
		SiteAID:  orgAID,
		SiteOOBI: orgOOBI,
	}
	if err := s.assetHandler.Store.CreateEmployeeInvite(inv); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	askToken, aerr := s.mintSignerAsk(orgName, orgAID, orgOOBI, inv.Token)
	if aerr != nil {
		http.Error(w, aerr.Error(), http.StatusInternalServerError)
		return
	}

	scanWriteJSON(w, map[string]interface{}{
		"invite": inv,
		"token":  askToken,
		"url":    fmt.Sprintf("%s/i/%s", publicURL, askToken),
	})
}

// mintSignerAsk builds the signed offer a person scans, and returns the token
// that resolves to it.
//
// Extracted so the founding-signer invite and the owner ceremony mint the same
// thing. A second, parallel offer format would be one more thing to keep in
// step, and the agent on the other side already knows how to read this one.
func (s *CoreServer) mintSignerAsk(orgName, orgAID, orgOOBI, inviteToken string) (string, error) {
	_, pwOOBI, seed, err := s.mintPairwise("signer")
	if err != nil {
		return "", fmt.Errorf("mint signer: %w", err)
	}
	ask, _ := json.Marshal(map[string]interface{}{
		"v":            "ASK1",
		"t":            4,
		"org_name":     orgName,
		"org_aid":      orgAID,
		"org_oobi":     orgOOBI,
		"site_aid":     orgAID,
		"site_oobi":    orgOOBI,
		"invite_token": inviteToken,
		"signer_oobi":  pwOOBI,
	})
	sig, serr := login.SignAsk(ask, seed)
	if serr != nil {
		return "", fmt.Errorf("sign ask: %w", serr)
	}
	if signed, ierr := injectSig(ask, sig); ierr == nil {
		ask = signed
	}

	tb := make([]byte, 16)
	if _, rerr := rand.Read(tb); rerr != nil {
		return "", rerr
	}
	askToken := hex.EncodeToString(tb)
	mintedAsks.Lock()
	mintedAsks.m[askToken] = ask
	mintedAsks.Unlock()
	return askToken, nil
}

// handleRedeemSignerInvite is called by the signing individual's agent (t=4).
//
// It seals them as the organisation's owner authority, and records them on the
// roster as an active administrator.
//
// The sealing is the part that matters, and its absence was the bug. Redeeming
// used to write an employee row saying "Super Admin" and file a signature
// beside it as evidence — a string in a table with no cryptographic force.
// Nothing consulted it before acting, so ownerAuthority() fell through to its
// default of "this agent's own identity is the authority" and the organisation
// owned itself. On rented hardware that meant the box held the only key that
// mattered and nobody outside it could prove otherwise.
//
// Sealing here closes that by making the signer's key the one this agent
// answers to, which is what most operations already check.
func (s *CoreServer) handleRedeemSignerInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	var body struct {
		PairwiseAID   string `json:"pairwise_aid"`
		Name          string `json:"name"`
		OOBI          string `json:"oobi"`
		PublicKey     string `json:"public_key"`
		NextPublicKey string `json:"next_public_key"`
		VouchSig      string `json:"vouch_sig"`
		VouchPayload  string `json:"vouch_payload"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.PairwiseAID == "" || body.VouchSig == "" {
		http.Error(w, "pairwise_aid and vouch_sig required", http.StatusBadRequest)
		return
	}
	// A signer without a public key cannot be sealed, and an organisation whose
	// owner cannot be verified is the condition this ceremony exists to prevent.
	// Checked here with the other required fields, before anything reaches into
	// the roster — a request that cannot succeed should not touch subsystems on
	// its way to being refused.
	if body.PublicKey == "" {
		http.Error(w,
			"public_key is required: without it this organisation could not verify its own owner, "+
				"which is the condition this ceremony exists to prevent",
			http.StatusBadRequest)
		return
	}
	inv, ok := s.assetHandler.Store.GetEmployeeInvite(token)
	if !ok || inv.Revoked || !inv.IsSigner {
		http.Error(w, "invalid signer invite", http.StatusBadRequest)
		return
	}
	if inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses {
		http.Error(w, "signer invite already used", http.StatusBadRequest)
		return
	}
	emp := asset.Employee{
		PairwiseAID:  body.PairwiseAID,
		Name:         body.Name,
		Role:         "Super Admin",
		Status:       "active", // founding signer is active immediately
		InviteToken:  token,
		OOBI:         body.OOBI,
		IsSigner:     true,
		VouchSig:     body.VouchSig,
		VouchPayload: body.VouchPayload,
	}
	// If this invite belongs to an ownership ceremony, the key just presented is
	// one of several being collected — record it and, when the last person has
	// accepted, rotate. The founding path below is for the FIRST owner, where
	// there is nothing yet to rotate from.
	if ceremony, complete, cerr := s.recordAcceptance(
		token, body.PairwiseAID, body.PublicKey, body.NextPublicKey); cerr != nil {
		http.Error(w, "could not record your acceptance: "+cerr.Error(), http.StatusInternalServerError)
		return
	} else if ceremony != nil {
		_ = s.assetHandler.Store.IncrementEmployeeInviteUse(token)
		_ = s.assetHandler.Store.UpsertEmployee(emp)
		if complete {
			// The last acceptance is what applies it. Nobody has to remember to
			// come back and press a button, and there is no window in which
			// every owner has agreed and the organisation has not changed.
			s.completeCeremonyIfReady(ceremony)
		}
		scanWriteJSON(w, map[string]interface{}{
			"status":      "accepted",
			"owner":       body.PairwiseAID,
			"outstanding": ceremony.Outstanding(),
		})
		return
	}

	// Seal the signer as this agent's owner BEFORE anything is written down.
	//
	// Ordering is the whole point. If the roster were written first and sealing
	// then failed, the organisation would look founded — an active Super Admin
	// on the list — while still answering to nobody but itself. Sealing first
	// means a failure leaves an unfounded org that can be founded again, which
	// is a recoverable state rather than a misleading one.
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       body.PairwiseAID,
		PublicKey: body.PublicKey,
	}); err != nil {
		http.Error(w, "could not seal the owner: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.assetHandler.Store.UpsertEmployee(emp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.assetHandler.Store.IncrementEmployeeInviteUse(token)
	scanWriteJSON(w, map[string]string{
		"status": "active",
		"role":   "Super Admin",
		"owner":  body.PairwiseAID,
	})
}
