package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountLoginRoutes(r chi.Router) {
	r.Route("/login", func(r chi.Router) {
		if s.loginHandler != nil {
			r.Post("/start", s.loginHandler.HandleStart)
			r.Post("/preview", s.loginHandler.HandlePreview)
			r.Post("/approve", s.loginHandler.HandleApprove)
			r.Post("/decline", s.loginHandler.HandleDecline)
			r.Get("/pending", s.loginHandler.HandlePendingList)
		}
		// Issue a signed login challenge for an asset (available even without a
		// per-user loginHandler).
		r.Post("/challenge", s.handleCreateAssetChallenge)
		// The user's agent posts the completed assertion here; the browser polls for completion.
		r.Post("/callback", s.handleLoginCallback)
		r.Get("/challenge/{token}/status", s.handleChallengeStatus)
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

// handleCreateAssetChallenge issues a signed login challenge bound to an asset.
// POST /api/login/challenge — called by the asset owner / a relying party.
func (s *CoreServer) handleCreateAssetChallenge(w http.ResponseWriter, r *http.Request) {
	if s.assetHandler == nil || s.KeriDriver == nil {
		http.Error(w, "asset or keri driver not available", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		AssetID              string   `json:"asset_id"`
		Audience             string   `json:"audience"`
		RequestedDisclosures []string `json:"requested_disclosures"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.AssetID == "" {
		http.Error(w, "asset_id required", http.StatusBadRequest)
		return
	}

	assets := s.assetHandler.Store.ListAssets()
	var foundAsset *asset.Asset
	for i := range assets {
		if assets[i].ID == body.AssetID {
			a := assets[i]
			foundAsset = &a
			break
		}
	}
	if foundAsset == nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}

	// generate nonce + session token
	nonceB := make([]byte, 32)
	rand.Read(nonceB)
	nonce := base64.RawURLEncoding.EncodeToString(nonceB)

	sessB := make([]byte, 16)
	rand.Read(sessB)
	sessionToken := hex.EncodeToString(sessB)

	publicURL := s.getPublicURL(r)

	bundle := login.ChallengeBundle{
		V:                    "ASK1",
		T:                    1,
		SiteAID:              foundAsset.PairwiseAID,
		SiteOOBI:             fmt.Sprintf("%s/public/oobi/%s", publicURL, foundAsset.PairwiseAID),
		Audience:             body.Audience,
		Nonce:                nonce,
		Dt:                   time.Now().UTC().Format(time.RFC3339),
		Expiry:               time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
		RequestedDisclosures: body.RequestedDisclosures,
		CallbackURL:          fmt.Sprintf("%s/api/login/callback", publicURL),
		SessionToken:         sessionToken,
	}

	// Re-derive the asset's signing seed (controller root + asset SigningIndex) and sign the
	// challenge Go-native. Replaces the broken Python /sign-for-name path (the driver
	// holds no private keys, ADR-014, and the asset key used to be discarded at creation).
	if foundAsset.SigningIndex == 0 {
		http.Error(w, "asset has no signing key (re-create the asset to provision one)", http.StatusConflict)
		return
	}
	seed, derr := asset.AssetSigningSeed(s.DataDir, foundAsset.SigningIndex)
	if derr != nil {
		http.Error(w, "asset seed: "+derr.Error(), http.StatusInternalServerError)
		return
	}
	if err := login.SignChallengeForAsset(&bundle, seed); err != nil {
		http.Error(w, "sign failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// store (cap 1000 simple)
	s.challengeMu.Lock()
	if s.challenges == nil {
		s.challenges = make(map[string]login.ChallengeBundle)
	}
	if s.challengeStatus == nil {
		s.challengeStatus = make(map[string]map[string]interface{})
	}
	if len(s.challenges) > 1000 {
		// naive: clear oldest? for now just overwrite or drop
		for k := range s.challenges {
			delete(s.challenges, k)
			break
		}
	}
	s.challenges[sessionToken] = bundle
	s.challengeStatus[sessionToken] = map[string]interface{}{"status": "pending"}
	s.challengeMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": sessionToken,
		"qr_url":        fmt.Sprintf("%s/i/%s", publicURL, sessionToken),
	})
}

// GET /i/{token} — public endpoint the IA fetches to get the signed bundle
func (s *CoreServer) handleChallengeBundleServe(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	s.challengeMu.Lock()
	b, ok := s.challenges[token]
	s.challengeMu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b)
}

// mount the /i route at root (called from buildRouter)
func (s *CoreServer) mountChallengeBundleRoute(r chi.Router) {
	r.Get("/i/{token}", s.handleChallengeBundleServe)
}

// Also expose a way to add the POST under /api/login
func (s *CoreServer) mountAssetLoginChallenge(r chi.Router) {
	r.Route("/login", func(r chi.Router) {
		r.Post("/challenge", s.handleCreateAssetChallenge)
	})
}

// POST /api/login/callback — mobile app posts completed assertion here
func (s *CoreServer) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	token, _ := body["session_token"].(string)
	if token == "" {
		token = r.URL.Query().Get("session")
	}
	if token == "" {
		http.Error(w, "session_token required", http.StatusBadRequest)
		return
	}
	pairwiseAID, _ := body["pairwise_aid"].(string)
	s.challengeMu.Lock()
	if s.challengeStatus == nil {
		s.challengeStatus = make(map[string]map[string]interface{})
	}
	s.challengeStatus[token] = map[string]interface{}{
		"status":       "complete",
		"pairwise_aid": pairwiseAID,
	}
	s.challengeMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// GET /api/login/challenge/{token}/status — browser polls this
func (s *CoreServer) handleChallengeStatus(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	s.challengeMu.Lock()
	st := s.challengeStatus[token]
	s.challengeMu.Unlock()
	if st == nil {
		st = map[string]interface{}{"status": "pending"}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}
