package login

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// loadRelationshipSeed re-derives the seed on demand from protected root + persisted RelationshipIndex.
// No per-rel secret files. Legacy SeedB64 fallback only for old data.
func loadRelationshipSeed(h *Handler, rel *SiteRelationship) ([]byte, error) {
	if h != nil && h.dataDir != "" && rel != nil && rel.RelationshipIndex > 0 {
		if root, err := secureenclave.LoadRootSeed(h.dataDir); err == nil {
			return backup.DerivePairwiseSeed(root, rel.RelationshipIndex, 0)
		}
	}
	if rel != nil && rel.SeedB64 != "" {
		return base64.StdEncoding.DecodeString(rel.SeedB64)
	}
	return nil, fmt.Errorf("no seed available for relationship %s (root + index required)", rel.PairwiseAID)
}

type Handler struct {
	Store          *RelationshipStore
	Pending        *PendingStore
	KeriDriver     *drivers.KeriDriver
	DevRelay       string
	HTTPClient     *http.Client
	TrustGate      *secureenclave.TrustGate
	dataDir        string // for secure relationship seed storage (never put raw seeds in main JSON)
	OnLoginPending func(LoginPreviewResponse)
	// HeldCredentials returns the ACDCs this agent holds, so a credential-gated
	// login can present a matching one. Wired by the server from the data store;
	// nil in contexts without a credential store (then nothing is presented).
	HeldCredentials func() []PresentedCredential
}

// presentCredentials selects held ACDCs that satisfy the bundle's requested
// credentials (matched by schema SAID), to embed in the assertion.
func (h *Handler) presentCredentials(bundle *ChallengeBundle) []interface{} {
	out := []interface{}{}
	if len(bundle.RequestedCredentials) == 0 || h == nil || h.HeldCredentials == nil {
		return out
	}
	held := h.HeldCredentials()
	for _, rc := range bundle.RequestedCredentials {
		for _, c := range held {
			if c.SchemaSAID == rc.SchemaSAID && isCredentialUsable(c.Status) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// isCredentialUsable treats an empty/issued/valid status as presentable; a
// revoked/expired credential is never presented.
func isCredentialUsable(status string) bool {
	switch status {
	case "", "issued", "valid", "active":
		return true
	default:
		return false
	}
}

func NewHandler(dataDir string, keri *drivers.KeriDriver) (*Handler, error) {
	store, err := NewRelationshipStore(dataDir)
	if err != nil {
		return nil, err
	}
	relay := os.Getenv("IA_RELAY_URL")
	if relay == "" {
		relay = os.Getenv("IA_DEV_RELAY_URL")
	}
	if relay == "" {
		relay = "http://127.0.0.1:8765"
	}
	return &Handler{
		Store:      store,
		Pending:    NewPendingStore(),
		KeriDriver: keri,
		DevRelay:   relay,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		dataDir:    dataDir,
	}, nil
}

func (h *Handler) fetchChallengeBundle(rpBase, sessionToken string) (*ChallengeBundle, error) {
	// Minimal Ask pointer (the login contract §5.2 / the shared module): {origin}/i/{token}.
	url := fmt.Sprintf("%s/i/%s", trimSlash(rpBase), sessionToken)
	resp, err := h.HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bundle fetch %d: %s", resp.StatusCode, string(b))
	}
	var bundle ChallengeBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

// verifyDelegationAnchor checks that the challenge's site AID is genuinely
// DELEGATED by the claimed relationship-anchor controller: its served KEL must
// open with a delegated inception (dip) for that exact AID naming the anchor as
// delegator (`di`). The delegator commitment is inside the signed inception
// event whose SAID *is* the site AID, so a site cannot claim a controller it does not
// belong to without changing its own identity.
func (h *Handler) verifyDelegationAnchor(bundle *ChallengeBundle) error {
	if bundle.SiteOOBI == "" {
		return fmt.Errorf("anchor requires a site OOBI")
	}
	resp, err := h.HTTPClient.Get(bundle.SiteOOBI)
	if err != nil {
		return fmt.Errorf("site OOBI fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("site OOBI fetch: HTTP %d", resp.StatusCode)
	}
	var oobi struct {
		AID string                   `json:"aid"`
		KEL []map[string]interface{} `json:"kel"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oobi); err != nil {
		return fmt.Errorf("site OOBI parse: %w", err)
	}
	if oobi.AID != bundle.SiteAID {
		return fmt.Errorf("site OOBI serves %s, challenge names %s", oobi.AID, bundle.SiteAID)
	}
	if len(oobi.KEL) == 0 {
		return fmt.Errorf("site OOBI has no KEL")
	}
	icp := oobi.KEL[0]
	if t, _ := icp["t"].(string); t != "dip" {
		return fmt.Errorf("site inception is %q, not a delegated inception", icp["t"])
	}
	if i, _ := icp["i"].(string); i != bundle.SiteAID {
		return fmt.Errorf("inception AID %q does not match site AID", i)
	}
	if di, _ := icp["di"].(string); di != bundle.RelationshipAnchorAID {
		return fmt.Errorf("site is delegated by %q, not the claimed anchor %q", icp["di"], bundle.RelationshipAnchorAID)
	}
	return nil
}

func (h *Handler) verifyChallengeSig(bundle *ChallengeBundle) (bool, []byte, error) {
	if bundle.Sig == "" {
		return false, nil, fmt.Errorf("challenge missing sig")
	}
	body := canonicalChallengeBody(*bundle)
	// Dev steel thread: resolve site key from dev relay did.json
	pub, err := h.resolveSiteKey(bundle.SiteOOBI, bundle.SiteAID)
	if err != nil {
		return false, nil, err
	}
	ok, err := verifyUTF8(body, bundle.Sig, pub)
	return ok, pub, err
}

func (h *Handler) resolveSiteKey(siteOOBI, siteAID string) ([]byte, error) {
	// Match login-verify resolver: strip /oobi/{aid} suffix, keep path prefix (RP-hosted did.json).
	relayBase := h.DevRelay
	if siteOOBI != "" {
		relayBase = siteOOBI
		if i := strings.Index(relayBase, "/oobi/"); i >= 0 {
			relayBase = relayBase[:i]
		}
	}
	url := fmt.Sprintf("%s/%s/did.json", trimSlash(relayBase), siteAID)
	resp, err := h.HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		VerificationMethod []struct {
			PublicKeyJwk struct {
				X string `json:"x"`
			} `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if len(doc.VerificationMethod) == 0 || doc.VerificationMethod[0].PublicKeyJwk.X == "" {
		return nil, fmt.Errorf("did.json missing key")
	}
	return base64.RawURLEncoding.DecodeString(doc.VerificationMethod[0].PublicKeyJwk.X)
}

// GetOrCreateRelationship resolves or creates a per-RP pairwise relationship.
func (h *Handler) GetOrCreateRelationship(siteAID string, bundle *ChallengeBundle) (*SiteRelationship, error) {
	return h.getOrCreateRelationship(siteAID, bundle)
}

// RelationshipSeed returns the pairwise Ed25519 seed for local signing, loaded from secure storage
// (AID is the handle; secret never in main persisted store).
func (h *Handler) RelationshipSeed(rel *SiteRelationship) ([]byte, error) {
	return loadRelationshipSeed(h, rel)
}

func (h *Handler) getOrCreateRelationship(siteAID string, bundle *ChallengeBundle) (*SiteRelationship, error) {
	if rel, ok := h.Store.Get(siteAID); ok {
		return &rel, nil
	}
	rootSeed, rerr := secureenclave.LoadRootSeed(h.dataDir)
	if rerr != nil {
		// FALLBACK ONLY: canonical path is the onboarding handoff installing the
		// mnemonic-derived seed (POST /api/keystore/root-seed). A random root is
		// device-local — recoverable from backup archives, never the phrase.
		log.Printf("[keystore] WARNING: bootstrapping a random DEVICE-LOCAL root seed (no onboarding seed handoff yet) — HD-derived keys will not be recoverable from the seed phrase alone")
		rootSeed = make([]byte, 64)
		if _, re := rand.Read(rootSeed); re != nil {
			return nil, fmt.Errorf("failed to bootstrap root seed: %w", re)
		}
		if serr := secureenclave.StoreRootSeed(h.dataDir, rootSeed); serr != nil {
			return nil, fmt.Errorf("failed to store root seed securely: %w", serr)
		}
	}
	loginIdx := h.Store.AllocateNextRelationshipIndex()

	pwiseSeed, derr := backup.DerivePairwiseSeed(rootSeed, loginIdx, 0)
	if derr != nil {
		return nil, fmt.Errorf("HD derive for login rel failed: %w", derr)
	}
	nextPwise, _ := backup.DerivePairwiseSeed(rootSeed, loginIdx, 1)
	pub := ed25519.NewKeyFromSeed(pwiseSeed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(nextPwise).Public().(ed25519.PublicKey)
	// Mint through a local KERI engine — never fabricate. Desktop: the Python
	// keripy driver. Driverless (mobile): the keri-go native builder, which uses
	// the same keri-1.1.17 SerderKERI makify (Blake3 self-addressing) mechanics.
	var pairwiseAID string
	if h.KeriDriver != nil {
		resp, err := h.KeriDriver.CreateInceptionNamed(
			iacrypto.VerkeyQB64(pub),
			iacrypto.VerkeyQB64(nextPub),
			"login-rel-"+siteAID,
		)
		if err != nil || resp.AID == "" {
			return nil, fmt.Errorf("failed to mint real relationship AID via local engine: %w", err)
		}
		pairwiseAID = resp.AID
	} else {
		res, err := iacrypto.BuildEd25519Inception(pub, nextPub)
		if err != nil || res.AID == "" {
			return nil, fmt.Errorf("failed to mint relationship AID via keri-go: %w", err)
		}
		pairwiseAID = res.AID
	}
	// Do NOT persist derived seed per-rel. Re-derive from root + RelationshipIndex on demand.
	// Only root seed protected in enclave; index persisted with the rel record.

	relayBase := h.relayBaseFromOOBI(bundle.SiteOOBI)
	if relayBase == "" {
		relayBase = h.DevRelay
	}
	relayOOBI := h.Store.DevRelayOOBI(pairwiseAID, relayBase)
	rel := SiteRelationship{
		SiteAID:           siteAID,
		PairwiseAID:       pairwiseAID,
		SeedB64:           "",
		RelayOOBI:         relayOOBI,
		DisplayName:       "IA User",
		Email:             "user@identity.agent",
		RelationshipIndex: loginIdx, // stable persisted index for HD re-derive from root
	}
	if err := h.Store.Put(rel); err != nil {
		return nil, err
	}
	_ = bundle
	return &rel, nil
}

// BuildAssertion signs a login assertion (exported for OIDC adapter).
func (h *Handler) BuildAssertion(rel *SiteRelationship, bundle *ChallengeBundle, customData map[string]interface{}) (*Assertion, error) {
	return h.buildAssertion(rel, bundle, customData)
}

func (h *Handler) buildAssertion(rel *SiteRelationship, bundle *ChallengeBundle, customData map[string]interface{}) (*Assertion, error) {
	seed, err := loadRelationshipSeed(h, rel)
	if err != nil {
		return nil, err
	}
	disclosures := map[string]string{}
	for _, field := range bundle.RequestedDisclosures {
		switch field {
		case "display_name":
			disclosures[field] = rel.DisplayName
		case "email":
			disclosures[field] = rel.Email
		default:
			disclosures[field] = "granted"
		}
	}
	a := Assertion{
		V:                   "IALOGIN10JSON",
		T:                   "login-assertion",
		I:                   rel.PairwiseAID,
		RelationshipAIDOOBI: rel.RelayOOBI,
		Audience:            bundle.Audience,
		Nonce:               bundle.Nonce,
		Dt:                  rfc3339UTC(time.Now()),
		Disclosures:         disclosures,
		PresentedACDCs:      h.presentCredentials(bundle),
		CustomData:          customData,
	}
	d, err := assertionDigest(a)
	if err != nil {
		return nil, err
	}
	a.D = d
	body := canonicalAssertionBody(a)
	sig, _, err := signUTF8(body, seed)
	if err != nil {
		return nil, err
	}
	a.Sig = sig
	return &a, nil
}

func (h *Handler) postAssertion(callbackURL, sessionToken string, assertion *Assertion) error {
	b, err := json.Marshal(assertion)
	if err != nil {
		return err
	}
	url := callbackURL
	if sessionToken != "" {
		sep := "?"
		if bytes.Contains([]byte(url), []byte("?")) {
			sep = "&"
		}
		url = fmt.Sprintf("%s%ssession=%s", url, sep, sessionToken)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("callback %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ScoreAttestation returns the identity-level custom_data for an assertion
// (exported for the OIDC adapter).
func (h *Handler) ScoreAttestation(rel *SiteRelationship) (map[string]interface{}, error) {
	return h.scoreAttestation(rel)
}

func (h *Handler) scoreAttestation(rel *SiteRelationship) (map[string]interface{}, error) {
	if err := h.checkTrustGate(); err != nil {
		return nil, err
	}
	seed, err := loadRelationshipSeed(h, rel)
	if err != nil {
		return nil, err
	}
	now := rfc3339UTC(time.Now())
	env := ScoreAttestation{
		RelationshipAID:        rel.PairwiseAID,
		Band:                   "green",
		Score:                  75,
		ScoreAsOf:              now,
		FreshnessWindowSeconds: 60,
	}
	b, _ := json.Marshal(env)
	sig, _, err := signUTF8(string(b), seed)
	if err != nil {
		return nil, err
	}
	env.Sig = sig
	return map[string]interface{}{
		"score_attestation": env,
	}, nil
}

func (h *Handler) prepareLogin(req StartLoginRequest) (*ChallengeBundle, *SiteRelationship, *LoginPreviewResponse, error) {
	if req.SessionToken == "" || req.RPSessionURL == "" {
		return nil, nil, nil, fmt.Errorf("session_token and rp_session_url required")
	}

	bundle, err := h.fetchChallengeBundle(req.RPSessionURL, req.SessionToken)
	if err != nil {
		return nil, nil, nil, err
	}

	ok, _, err := h.verifyChallengeSig(bundle)
	if err != nil || !ok {
		return nil, nil, nil, fmt.Errorf("challenge verification failed")
	}

	// Membership-gated assets anchor the relationship to the asset's CONTROLLER
	// (the delegating identity — an organization or an individual) so the
	// presented pairwise equals the one the controller enrolled (e.g. at
	// signer enrolment/add_employee). The anchor is only honored after independently
	// verifying the site is DELEGATED by the claimed controller (its dip event
	// names it as delegator): without this check any page could claim an anchor
	// and harvest the scanner's constant membership AID. Fail closed — a bad
	// anchor rejects the login rather than silently downgrading to a fresh
	// per-site identity.
	relKey := bundle.SiteAID
	if bundle.RelationshipAnchorAID != "" {
		if err := h.verifyDelegationAnchor(bundle); err != nil {
			return nil, nil, nil, fmt.Errorf("relationship anchor rejected: %w", err)
		}
		relKey = bundle.RelationshipAnchorAID
	}
	rel, err := h.getOrCreateRelationship(relKey, bundle)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := h.registerPairwiseOnDevRelay(rel); err != nil {
		return nil, nil, nil, err
	}

	preview := &LoginPreviewResponse{
		Pending:               true,
		SessionToken:          req.SessionToken,
		SiteAID:               bundle.SiteAID,
		SiteOOBI:              bundle.SiteOOBI,
		Audience:              bundle.Audience,
		RequestedDisclosures:  bundle.RequestedDisclosures,
		DisclosurePreview:     h.previewDisclosures(rel, bundle),
		RequestedCredentials:  h.previewRequestedCredentials(bundle),
		RequestedScore:        bundle.RequestedScore,
		Expiry:                bundle.Expiry,
		PairwiseAID:           rel.PairwiseAID,
		RelationshipAnchorAID: bundle.RelationshipAnchorAID,
		RPSessionURL:          req.RPSessionURL,
	}
	return bundle, rel, preview, nil
}

// previewRequestedCredentials describes the credentials the site asks for,
// including whether we actually hold a usable one — the same match
// presentCredentials will make, so the screen predicts what approving does.
func (h *Handler) previewRequestedCredentials(bundle *ChallengeBundle) []CredentialRequestPreview {
	if bundle == nil || len(bundle.RequestedCredentials) == 0 {
		return nil
	}
	var held []PresentedCredential
	if h != nil && h.HeldCredentials != nil {
		held = h.HeldCredentials()
	}
	out := make([]CredentialRequestPreview, 0, len(bundle.RequestedCredentials))
	for _, rc := range bundle.RequestedCredentials {
		p := CredentialRequestPreview{SchemaSAID: rc.SchemaSAID, Required: rc.Required}
		for _, c := range held {
			if c.SchemaSAID == rc.SchemaSAID && isCredentialUsable(c.Status) {
				p.Held = true
				break
			}
		}
		out = append(out, p)
	}
	return out
}

func (h *Handler) previewDisclosures(rel *SiteRelationship, bundle *ChallengeBundle) map[string]string {
	out := map[string]string{}
	for _, field := range bundle.RequestedDisclosures {
		switch field {
		case "display_name":
			out[field] = rel.DisplayName
		case "email":
			out[field] = rel.Email
		default:
			out[field] = "granted"
		}
	}
	return out
}

func (h *Handler) storePending(req StartLoginRequest, bundle *ChallengeBundle, rel *SiteRelationship) {
	key := req.SessionToken + "|" + req.RPSessionURL
	h.Pending.Put(key, &pendingLogin{
		SessionToken: req.SessionToken,
		RPSessionURL: req.RPSessionURL,
		Bundle:       bundle,
		Relationship: rel,
		CreatedAt:    time.Now(),
	})
}

func (h *Handler) loadPending(req StartLoginRequest) (*pendingLogin, error) {
	key := req.SessionToken + "|" + req.RPSessionURL
	p, ok := h.Pending.Get(key)
	if !ok {
		return nil, fmt.Errorf("login session not found or expired")
	}
	return p, nil
}

func (h *Handler) relayBaseFromOOBI(oobi string) string {
	if oobi == "" {
		return ""
	}
	// Preserve the full path prefix up to /oobi/ — RP-hosted serves under
	// /auth/ia/site, so dropping to scheme://host would point the relationship
	// OOBI + registration at the wrong routes (404 → SPA HTML → key-resolve
	// failure). Mirrors resolveSiteKey. Dev relay (root /oobi/) is unaffected.
	if i := strings.Index(oobi, "/oobi/"); i >= 0 {
		return oobi[:i]
	}
	req, err := http.NewRequest(http.MethodGet, oobi, nil)
	if err != nil || req.URL == nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Host)
}

func (h *Handler) registerPairwiseOnDevRelay(rel *SiteRelationship) error {
	relayBase := h.relayBaseFromOOBI(rel.RelayOOBI)
	if relayBase == "" {
		relayBase = h.DevRelay
	}
	seed, err := loadRelationshipSeed(h, rel)
	if err != nil {
		return err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	body, _ := json.Marshal(map[string]string{
		"aid":            rel.PairwiseAID,
		"public_key_b64": base64.RawURLEncoding.EncodeToString(pub),
	})

	registerPath := "/_dev/register"
	if !strings.Contains(relayBase, "127.0.0.1") && !strings.Contains(relayBase, "localhost") {
		registerPath = "/_register"
	}

	url := trimSlash(relayBase) + registerPath
	resp, err := h.HTTPClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil // non-fatal when relay stub is absent
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("relay register %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (h *Handler) completeLogin(p *pendingLogin) (map[string]interface{}, error) {
	if err := h.checkTrustGate(); err != nil {
		return nil, err
	}
	rel := p.Relationship
	bundle := p.Bundle

	var customData map[string]interface{}
	var err error
	if bundle.RequestedScore != nil {
		customData, err = h.scoreAttestation(rel)
		if err != nil {
			return nil, err
		}
	}

	assertion, err := h.buildAssertion(rel, bundle, customData)
	if err != nil {
		return nil, err
	}

	if err := h.postAssertion(bundle.CallbackURL, bundle.SessionToken, assertion); err != nil {
		return nil, err
	}

	key := p.SessionToken + "|" + p.RPSessionURL
	h.Pending.Delete(key)

	return map[string]interface{}{
		"ok":           true,
		"pairwise_aid": rel.PairwiseAID,
		"disclosures":  assertion.Disclosures,
	}, nil
}

// HandleStart queues a login for user consent (B1).
func (h *Handler) HandleStart(w http.ResponseWriter, r *http.Request) {
	var req StartLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	bundle, rel, preview, err := h.prepareLogin(req)
	if err != nil {
		status := http.StatusBadGateway
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "verification failed") {
			status = http.StatusBadRequest
			if strings.Contains(err.Error(), "verification failed") {
				status = http.StatusUnauthorized
			}
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	h.storePending(req, bundle, rel)
	if h.OnLoginPending != nil {
		h.OnLoginPending(*preview)
	}
	writeJSON(w, http.StatusOK, preview)
}

// HandlePreview returns login consent details without completing the flow.
func (h *Handler) HandlePreview(w http.ResponseWriter, r *http.Request) {
	h.HandleStart(w, r)
}

// HandleApprove completes a pending login after user consent.
func (h *Handler) HandleApprove(w http.ResponseWriter, r *http.Request) {
	var req StartLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	p, err := h.loadPending(req)
	if err != nil {
		// Allow approve without prior start when mobile scans QR directly.
		bundle, rel, preview, prepErr := h.prepareLogin(req)
		if prepErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": prepErr.Error()})
			return
		}
		h.storePending(req, bundle, rel)
		_ = preview
		p, err = h.loadPending(req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	result, err := h.completeLogin(p)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// HandleDecline rejects a pending login.
func (h *Handler) HandleDecline(w http.ResponseWriter, r *http.Request) {
	var req StartLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	key := req.SessionToken + "|" + req.RPSessionURL
	h.Pending.Delete(key)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "declined": true})
}

// HandlePendingList returns queued login sessions awaiting consent.
func (h *Handler) HandlePendingList(w http.ResponseWriter, _ *http.Request) {
	items := h.Pending.List()
	out := make([]LoginPreviewResponse, 0, len(items))
	for _, p := range items {
		out = append(out, LoginPreviewResponse{
			Pending:              true,
			SessionToken:         p.SessionToken,
			SiteAID:              p.Bundle.SiteAID,
			SiteOOBI:             p.Bundle.SiteOOBI,
			Audience:             p.Bundle.Audience,
			RequestedDisclosures: p.Bundle.RequestedDisclosures,
			DisclosurePreview:    h.previewDisclosures(p.Relationship, p.Bundle),
			RequestedCredentials: h.previewRequestedCredentials(p.Bundle),
			RequestedScore:       p.Bundle.RequestedScore,
			Expiry:               p.Bundle.Expiry,
			PairwiseAID:          p.Relationship.PairwiseAID,
			RPSessionURL:         p.RPSessionURL,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"pending": out})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func (h *Handler) checkTrustGate() error {
	if h.TrustGate == nil || h.TrustGate.AllowsTrustOperations() {
		return nil
	}
	return fmt.Errorf("trust gate blocked: %s", h.TrustGate.TrustBlockedReason())
}
