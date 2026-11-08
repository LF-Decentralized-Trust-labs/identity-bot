package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/internal/jsonreply"
)

// createSignedAssetChallenge builds, signs, and stores a login challenge bundle for an
// asset, returning the session token + the QR/bundle URL. errCode==0 means success;
// otherwise (errCode, errMsg) is an HTTP error to surface. Shared by the native
// /api/login/challenge endpoint and the widget-compatible /api/login/session endpoint.
//
// askedFrom is the origin of the web page that asked, from the Origin header its
// browser sent, or "" when a server asked. A page cannot choose its Origin, so
// it is the audience: a sign-in asked for from a page is for that page and no
// other, and an asset that names the origin of its website is not signed in to
// from any other page.
func (s *CoreServer) createSignedAssetChallenge(assetID, audience, askedFrom string, disclosures []string, browserKey, publicURL string) (sessionToken, qrURL string, errCode int, errMsg string) {
	if s.assetHandler == nil || s.KeriDriver == nil {
		return "", "", http.StatusServiceUnavailable, "asset or keri driver not available"
	}
	var found *asset.Asset
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		return "", "", http.StatusInternalServerError, "asset store unreadable: " + err.Error()
	}
	for _, a := range assets {
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

	if askedFrom != "" {
		if askedFrom == "null" {
			return "", "", http.StatusBadRequest, "this page has no origin to sign in to"
		}
		if audience != "" && audience != askedFrom {
			return "", "", http.StatusBadRequest, "a page signs in to its own origin only"
		}
		audience = askedFrom
		if found.Origin != "" && !sameOrigin(found.Origin, askedFrom) {
			return "", "", http.StatusForbidden, "this website asset is not for this page"
		}
	}

	// A sign-in for a browser's key names its thumbprint in the signed
	// challenge, so the person's approval is for that key (ADR-066).
	if browserKey != "" {
		if err := login.CheckBrowserKeyThumbprint(browserKey); err != nil {
			return "", "", http.StatusBadRequest, err.Error()
		}
	}

	nonceB := make([]byte, 32)
	rand.Read(nonceB)
	sessB := make([]byte, 16)
	rand.Read(sessB)
	sessionToken = hex.EncodeToString(sessB)

	// A credential-gated asset asks the signer to present the required ACDC.
	var reqCreds []login.RequestedCredential
	if found.Policy.RequiredCredSchema != "" {
		reqCreds = append(reqCreds, login.RequestedCredential{
			SchemaSAID: found.Policy.RequiredCredSchema,
			Required:   true,
		})
	}

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
		RequestedCredentials: reqCreds,
		CallbackURL:          fmt.Sprintf("%s/api/login/callback", publicURL),
		SessionToken:         sessionToken,
		BrowserKey:           browserKey,
	}
	// Membership-gated asset: anchor the relationship to the asset's CONTROLLER
	// (its delegator — an organization or an individual), not the per-asset AID,
	// so the signer presents the same constant pairwise it enrolled with
	// (signer enrolment / add_employee) — "prove you're the identity the controller
	// already knows" instead of creating a fresh per-site account. The scanner
	// independently verifies the delegation (the asset's dip event) before
	// honoring the anchor.
	if src := found.Policy.MembershipSource; src != "" && src != "asset" && found.DelegatorAID != "" {
		bundle.RelationshipAnchorAID = found.DelegatorAID
		bundle.RelationshipAnchorOOBI = fmt.Sprintf("%s/public/oobi/%s", publicURL, found.DelegatorAID)
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
	// Results nobody collected within their window are forgotten first. A
	// failure to record that is not a reason to refuse a new sign-in; the
	// tick tries again.
	if _, err := s.forgetUncollectedResultsLocked(time.Now()); err != nil {
		log.Printf("[identity-agent-core] could not forget uncollected sign-in results: %v", err)
	}
	if len(s.challenges) > 1000 {
		for k := range s.challenges {
			delete(s.challenges, k)
			delete(s.challengeStatus, k)
			delete(s.challengeCollector, k)
			break
		}
	}
	s.challenges[sessionToken] = bundle
	pending := map[string]interface{}{"status": "pending"}
	if askedFrom != "" {
		// Remembered with the sign-in, because only a page with no back end
		// is handed the assertion (see handleLoginSessionStatus).
		pending["asked_from_page"] = true
	}
	s.challengeStatus[sessionToken] = pending
	if err := s.saveChallengeStateLocked(); err != nil {
		// Fail closed: a sign-in the agent cannot record is one a restart
		// forgets, along with whether it was answered.
		delete(s.challenges, sessionToken)
		delete(s.challengeStatus, sessionToken)
		s.challengeMu.Unlock()
		log.Printf("[identity-agent-core] refusing to start a sign-in: %v", err)
		return "", "", http.StatusInternalServerError, "could not record the sign-in"
	}
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
		BrowserKey         string   `json:"browserKey"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // tolerate empty body
	token, qrURL, code, msg := s.createSignedAssetChallenge(assetID, body.Audience, r.Header.Get("Origin"), body.RequestDisclosures, body.BrowserKey, s.getPublicURL(r))
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	secret, serr := s.mintCollectorSecret(token)
	if serr != nil {
		http.Error(w, "could not start a login", http.StatusInternalServerError)
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]string{
		"session_token":   token,
		"relay_or_qr_url": qrURL,
		// Held by the browser that started this, and by nothing else.
		// Required to read who signed in. Never put it in a link or a QR code.
		"collector_secret": secret,
	})
}

// GET /api/login/session/{asset_id}/{token} — poll session state (SignInButton-compatible).
// Maps the internal challenge status to the SDK's state vocabulary.
//
// WHETHER somebody signed in is not the same secret as WHO. The session token
// travels in the QR code, so anybody who photographs a sign-in screen holds it.
// They may learn that the sign-in finished — the browser polling from the page
// needs that much to hand off to its own backend, and it reveals nothing about
// the person. They may not learn the identifier, the disclosures or the role,
// which are released only against the collector secret handed once to whoever
// created the session.
func (s *CoreServer) handleLoginSessionStatus(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	token := chi.URLParam(r, "token")

	offered := r.Header.Get("X-Collector-Secret")
	if offered == "" {
		offered = r.URL.Query().Get("collector")
	}

	st, bound, held, cerr := s.collectSignIn(token, offered, time.Now())
	if cerr != nil {
		http.Error(w, "could not read this sign-in", http.StatusInternalServerError)
		return
	}
	// A session created before this existed has nothing to check against, and
	// refusing it would break sign-ins already in flight across an upgrade.
	mayCollect := !bound || held

	resp := map[string]interface{}{"state": "connecting"}
	if st != nil {
		switch st["status"] {
		case "pending":
			// An answer was refused and the sign-in is still open: tell the
			// person's page why, so they can fix it and try again. The reason
			// can name the policy that refused, so it is held to the same
			// standard as the identity.
			if reason, ok := st["last_refusal"].(string); ok && mayCollect {
				resp["last_refusal"] = reason
			}
		case "complete":
			resp["state"] = "verified"
			if !mayCollect {
				// Say so rather than looking like a sign-in that carried no
				// identity, which is what a caller that has lost its secret
				// would otherwise conclude.
				resp["identity_withheld"] = true
				break
			}
			if st["released"] == true {
				// Collected already, or not collected in time: forgotten.
				resp["identity_withheld"] = true
				break
			}
			if p, ok := st["pairwise_aid"].(string); ok {
				resp["app_session_token"] = p
			}
			if d, ok := st["disclosures"]; ok {
				resp["disclosures"] = d
			}
			// What a page with no back end of its own checks the answer
			// against: the assertion, and the nonce and site of the
			// challenge it answers. Released with the identity, once, and
			// only when the sign-in was started from a page. The assertion
			// carries the credentials the person showed, and a collector that
			// is a page is any script in it; a server that asked keeps what
			// it always had.
			if a, ok := st["assertion"].(string); ok && held && st["asked_from_page"] == true {
				resp["assertion"] = a
				resp["nonce"] = st["nonce"]
				resp["site_aid"] = st["site_aid"]
			}
			// The browser key the verified assertion repeated (ADR-066): released
			// to the collector only, like who signed in.
			if bk, ok := st["browser_key"].(string); ok {
				resp["browser_key"] = bk
			}
			// Membership-admitted logins: who the admitting roster says this is
			// (e.g. role + display_name), so the RP needs no org-internal lookups.
			if mi, ok := st["member_info"]; ok {
				resp["member_info"] = mi
			}
		case "denied":
			resp["state"] = "declined"
			// A refusal reason can name the policy that refused, so it is held
			// to the same standard as the identity.
			if reason, ok := st["reason"].(string); ok && mayCollect {
				resp["reason"] = reason
			}
		}
	}
	jsonreply.Write(w, http.StatusOK, resp)
}

func corsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Collector-Secret")
}

func corsPreflight(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	w.WriteHeader(http.StatusNoContent)
}
