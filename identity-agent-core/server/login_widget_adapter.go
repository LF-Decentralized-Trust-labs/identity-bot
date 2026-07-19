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

// createSignedAssetChallenge builds, signs, and stores a login challenge bundle for an
// asset, returning the session token + the QR/bundle URL. errCode==0 means success;
// otherwise (errCode, errMsg) is an HTTP error to surface. Shared by the native
// /api/login/challenge endpoint and the widget-compatible /api/login/session endpoint.
func (s *CoreServer) createSignedAssetChallenge(assetID, audience string, disclosures []string, publicURL string) (sessionToken, qrURL string, errCode int, errMsg string) {
	if s.assetHandler == nil || s.KeriDriver == nil {
		return "", "", http.StatusServiceUnavailable, "asset or keri driver not available"
	}
	var found *asset.Asset
	for _, a := range s.assetHandler.Store.ListAssets() {
		if a.ID == assetID {
			aa := a
			found = &aa
			break
		}
	}
	if found == nil {
		return "", "", http.StatusNotFound, "asset not found"
	}
	if found.SigningIndex == 0 {
		return "", "", http.StatusConflict, "asset has no signing key (re-create the asset to provision one)"
	}

	nonceB := make([]byte, 32)
	rand.Read(nonceB)
	sessB := make([]byte, 16)
	rand.Read(sessB)
	sessionToken = hex.EncodeToString(sessB)

	bundle := login.ChallengeBundle{
		V:                    "ASK1",
		T:                    1,
		SiteAID:              found.PairwiseAID,
		SiteOOBI:             fmt.Sprintf("%s/public/oobi/%s", publicURL, found.PairwiseAID),
		Audience:             audience,
		Nonce:                base64.RawURLEncoding.EncodeToString(nonceB),
		Dt:                   time.Now().UTC().Format(time.RFC3339),
		Expiry:               time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
		RequestedDisclosures: disclosures,
		CallbackURL:          fmt.Sprintf("%s/api/login/callback", publicURL),
		SessionToken:         sessionToken,
	}
	seed, derr := asset.AssetSigningSeed(s.DataDir, found.SigningIndex)
	if derr != nil {
		return "", "", http.StatusInternalServerError, "asset seed: " + derr.Error()
	}
	if err := login.SignChallengeForAsset(&bundle, seed); err != nil {
		return "", "", http.StatusInternalServerError, "sign failed: " + err.Error()
	}

	s.challengeMu.Lock()
	if s.challenges == nil {
		s.challenges = make(map[string]login.ChallengeBundle)
	}
	if s.challengeStatus == nil {
		s.challengeStatus = make(map[string]map[string]interface{})
	}
	if len(s.challenges) > 1000 {
		for k := range s.challenges {
			delete(s.challenges, k)
			break
		}
	}
	s.challenges[sessionToken] = bundle
	s.challengeStatus[sessionToken] = map[string]interface{}{"status": "pending"}
	s.challengeMu.Unlock()

	return sessionToken, fmt.Sprintf("%s/i/%s", publicURL, sessionToken), 0, ""
}

// mountLoginWidgetRoutes mounts the login-web SignInButton-compatible endpoints. The widget
// is configured with sessionEndpoint = {orgIA}/api/login/session/{asset_id}; it POSTs to
// create a session and polls {sessionEndpoint}/{token}. This lets the unmodified SDK widget
// drop onto any site pointed at an Identity Agent (the relying party) + an asset id — no per-site backend.
func (s *CoreServer) mountLoginWidgetRoutes(r chi.Router) {
	r.Options("/api/login/session/{asset_id}", corsPreflight)
	r.Options("/api/login/session/{asset_id}/{token}", corsPreflight)
	r.Post("/api/login/session/{asset_id}", s.handleCreateLoginSession)
	r.Get("/api/login/session/{asset_id}/{token}", s.handleLoginSessionStatus)
}

// POST /api/login/session/{asset_id} — create a login session (SignInButton-compatible).
func (s *CoreServer) handleCreateLoginSession(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	assetID := chi.URLParam(r, "asset_id")
	var body struct {
		RequestDisclosures []string `json:"requestDisclosures"`
		Audience           string   `json:"audience"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // tolerate empty body
	token, qrURL, code, msg := s.createSignedAssetChallenge(assetID, body.Audience, body.RequestDisclosures, s.getPublicURL(r))
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"session_token":   token,
		"relay_or_qr_url": qrURL,
	})
}

// GET /api/login/session/{asset_id}/{token} — poll session state (SignInButton-compatible).
// Maps the internal challenge status to the SDK's state vocabulary.
func (s *CoreServer) handleLoginSessionStatus(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	token := chi.URLParam(r, "token")
	s.challengeMu.Lock()
	st := s.challengeStatus[token]
	s.challengeMu.Unlock()

	resp := map[string]interface{}{"state": "connecting"}
	if st != nil {
		switch st["status"] {
		case "complete":
			resp["state"] = "verified"
			if p, ok := st["pairwise_aid"].(string); ok {
				resp["app_session_token"] = p
			}
			if d, ok := st["disclosures"]; ok {
				resp["disclosures"] = d
			}
		case "denied":
			resp["state"] = "declined"
			if reason, ok := st["reason"].(string); ok {
				resp["reason"] = reason
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func corsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func corsPreflight(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	w.WriteHeader(http.StatusNoContent)
}
