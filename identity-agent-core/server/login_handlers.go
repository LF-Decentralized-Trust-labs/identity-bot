package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"identity-agent-core/schemas"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/login"
	"identity-agent-core/watcher"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/internal/jsonreply"
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

// acdcAsBase64 is the one place that decides how a held credential's body is
// encoded on the wire: standard base64 of the ACDC's exact bytes. Issued and
// delivered records already keep it that way and pass through unchanged; a
// record kept as plain JSON (one received by hand) is encoded here. Encoding a
// base64 body again is what made a site refuse genuine credentials.
func acdcAsBase64(stored string) string {
	if strings.HasPrefix(strings.TrimSpace(stored), "{") {
		return base64.StdEncoding.EncodeToString([]byte(stored))
	}
	return stored
}

func (s *CoreServer) initLoginHandler() error {
	h, err := login.NewHandler(s.DataDir, s.KeriDriver)
	if err != nil {
		return err
	}
	h.PeerClient = func(rawURL string) *http.Client { return siteClient(h.HTTPClient.Timeout, rawURL) }
	// Let a credential-gated login present a matching held ACDC.
	h.HeldCredentials = func() []login.PresentedCredential {
		recs, err := s.DataStore.GetCredentials()
		if err != nil {
			return nil
		}
		out := make([]login.PresentedCredential, 0, len(recs))
		for _, c := range recs {
			out = append(out, login.PresentedCredential{
				SAID:        c.SAID,
				SchemaSAID:  c.SchemaSAID,
				IssuerAID:   c.IssuerAID,
				HolderAID:   c.HolderAID,
				Status:      c.Status,
				AcdcJsonB64: acdcAsBase64(c.AcdcJson),
			})
		}
		return out
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
		BrowserKey           string   `json:"browser_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.AssetID == "" {
		http.Error(w, "asset_id required", http.StatusBadRequest)
		return
	}

	token, qrURL, code, msg := s.createSignedAssetChallenge(body.AssetID, body.Audience, body.RequestedDisclosures, body.BrowserKey, s.getPublicURL(r))
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
		"session_token": token,
		"qr_url":        qrURL,
		// Held by the browser that started this, and by nothing else.
		// Required to read the result. Never put it in a link or a QR code.
		"collector_secret": secret,
	})
}

// mintCollectorSecret gives the initiating browser something the QR code does
// not carry, and keeps only its hash.
func (s *CoreServer) mintCollectorSecret(token string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	s.challengeMu.Lock()
	if s.challengeCollector == nil {
		s.challengeCollector = map[string][32]byte{}
	}
	s.challengeCollector[token] = sum
	s.challengeMu.Unlock()
	return secret, nil
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
		// Fall back to an IA-minted Ask (e.g. an add-contact "add me" QR).
		if raw, mok := getMintedAsk(token); mok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	jsonreply.Write(w, http.StatusOK, b)
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

// POST /api/login/callback — the person's Identity Agent posts the signed assertion
// here. The assertion is the raw body; the session token is the ?session= query param.
//
// This VERIFIES the assertion before completing the session: the signature must check
// out against the key the assertion's own key log puts in force (p_kel, which must
// derive the asserter's identifier; nothing is fetched), it must name this site's
// challenge (site_aid) and its nonce and audience, it must be fresh, and the asserter
// must satisfy the asset's enrollment policy.
func (s *CoreServer) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	a, err := login.ReadAssertion(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := r.URL.Query().Get("session")
	if token == "" {
		http.Error(w, "session query param required", http.StatusBadRequest)
		return
	}

	s.challengeMu.Lock()
	bundle, ok := s.challenges[token]
	settled := s.challengeStatus[token] != nil &&
		s.challengeStatus[token]["status"] != "pending"
	s.challengeMu.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// A challenge that has already been answered is finished, whether the
	// answer admitted somebody or refused them. Without this, a copy of an
	// assertion already sent once can be posted again inside the freshness
	// window, needing no key and no forgery.
	if settled {
		http.Error(w, "this sign-in has already been answered", http.StatusConflict)
		return
	}

	// 1) Authenticate: verify the assertion signature + binding to this challenge.
	res := login.VerifyAssertionForBrowserKey(a, bundle.Nonce, bundle.Audience, bundle.SiteAID, bundle.BrowserKey, 300)
	if !res.Valid {
		s.setChallengeStatus(token, map[string]interface{}{"status": "denied", "reason": res.Reason})
		http.Error(w, "assertion verification failed: "+res.Reason, http.StatusUnauthorized)
		return
	}

	// 2) Authorize: enforce the asset's enrollment policy for the asserter,
	// including any required credential presented in the (verified) assertion.
	//
	// The SPECIFIC reason goes to the organisation, never to the caller.
	//
	// "not an active employee" told to whoever asked is an oracle: anybody who
	// can reach this endpoint learns, for an identifier they nominate, whether
	// that person works here — and by varying the policy, where the credential
	// and score thresholds sit. None of that requires being able to sign in.
	//
	// The reason is kept in the challenge status, which the site's own sign-in
	// page can read; only a uniform refusal leaves here. The owner is not shown
	// it: a gate the core cannot check is refused when the policy is saved.
	if allowed, reason := s.authorizeAssetAccess(r.Context(), bundle.SiteAID, res.PairwiseAID, a.PresentedACDCs); !allowed {
		s.setChallengeStatus(token, map[string]interface{}{
			"status": "denied",
			// For the organisation, which is entitled to know.
			"reason": reason,
		})
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}

	st := map[string]interface{}{
		"status":       "complete",
		"pairwise_aid": res.PairwiseAID,
		"disclosures":  res.Disclosures,
	}
	// The browser key the verified assertion repeated (ADR-066), so whoever
	// reads the result can check it is the one it asked for.
	if bundle.BrowserKey != "" {
		st["browser_key"] = a.BrowserKey
	}
	// Membership-admitted logins carry the member's info (role, display name)
	// from the admitting resolver, so the relying party gets "who this is" in
	// the login result instead of querying org-internal rosters.
	if info := s.memberInfoFor(bundle.SiteAID, res.PairwiseAID); len(info) > 0 {
		st["member_info"] = info
	}
	s.setChallengeStatus(token, st)
	jsonreply.Write(w, http.StatusOK, map[string]bool{"ok": true})
}

// memberInfoFor returns the admitting membership resolver's description of a
// member (e.g. role + display name) for the asset behind siteAID, when the
// resolver implements the optional MemberInfoResolver interface. Empty when the
// asset isn't membership-gated or the resolver has nothing to say.
func (s *CoreServer) memberInfoFor(siteAID, pairwiseAID string) map[string]string {
	if s.assetHandler == nil {
		return nil
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		log.Printf("[identity-agent-core] no member info, the asset store is unreadable: %v", err)
		return nil
	}
	for _, a := range assets {
		if a.PairwiseAID != siteAID {
			continue
		}
		if src := a.Policy.MembershipSource; src != "" && src != "asset" {
			if r := membershipResolverFor(src); r != nil {
				if ir, ok := r.(MemberInfoResolver); ok {
					if info, found := ir.MemberInfo(pairwiseAID, a.ID); found {
						return info
					}
				}
			}
		}
		return nil
	}
	return nil
}

// setChallengeStatus stores a session's status under the challenge lock.
func (s *CoreServer) setChallengeStatus(token string, st map[string]interface{}) {
	s.challengeMu.Lock()
	if s.challengeStatus == nil {
		s.challengeStatus = make(map[string]map[string]interface{})
	}
	s.challengeStatus[token] = st
	s.challengeMu.Unlock()
}

// authorizeAssetAccess enforces an asset's enrollment policy for an asserter.
// Requirements are ADDITIVE: the enrollment mode ("open" admits any verified
// identity; otherwise the pairwise AID must be a member) AND, if the policy sets
// a required credential, a matching valid ACDC must be present in the verified
// assertion. `presented` is the assertion's presented_acdcs.
func (s *CoreServer) authorizeAssetAccess(ctx context.Context, siteAID, pairwiseAID string, presented []interface{}) (bool, string) {
	if s.assetHandler == nil {
		return false, "asset store unavailable"
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		// Fail closed: an asset store that cannot be read admits nobody.
		return false, "asset store unreadable: " + err.Error()
	}
	for _, a := range assets {
		if a.PairwiseAID != siteAID {
			continue
		}
		if ok, reason := s.admitsMember(a, pairwiseAID); !ok {
			return false, reason
		}
		// Credential gate (additive).
		if a.Policy.RequiredCredSchema != "" {
			if ok, reason := s.credentialGateSatisfied(ctx, presented, pairwiseAID, a.Policy.RequiredCredSchema, a.Policy.RequiredCredIssuer); !ok {
				return false, reason
			}
		}
		// Score, badge and assurance-level gates. The core has no step that
		// checks any of them, so a policy that sets one cannot be satisfied:
		// refuse and name the gate, never pass it silently. (Saving such a
		// policy is refused too, so this only meets one stored earlier.)
		if g := a.Policy.UnsupportedGate(); g != "" {
			return false, g
		}
		return true, ""
	}
	return false, "asset not found"
}

// admitsMember is the enrolment-mode gate of an asset's policy: whether the
// pairwise identifier is one the asset's policy lets in, by membership. It is
// the part of authorizeAssetAccess that does not depend on what a person
// presented, so it can be asked again later of someone already signed in.
func (s *CoreServer) admitsMember(a asset.Asset, pairwiseAID string) (bool, string) {
	// Enrollment mode gate. A non-default MembershipSource is resolved by a
	// registered MembershipResolver (org overlays register e.g. "employees");
	// the default ("" / "asset") checks this asset's own member list. An
	// unrecognized source with no resolver fails closed.
	if a.Policy.Mode != asset.EnrollmentOpen {
		if src := a.Policy.MembershipSource; src != "" && src != "asset" {
			r := membershipResolverFor(src)
			if r == nil {
				return false, "no membership resolver for source: " + src
			}
			if ok, reason := r.Admit(pairwiseAID, a.ID); !ok {
				return false, reason
			}
		} else {
			member := false
			for _, m := range s.assetHandler.Store.ListMembers(a.ID) {
				if m.PairwiseAID == pairwiseAID {
					member = true
					break
				}
			}
			if !member {
				return false, "not a member of this asset"
			}
		}
	}
	return true, ""
}

// credentialGateSatisfied returns true if the presented ACDCs include one that
// satisfies the required schema (and issuer). When the KERI driver + raw ACDC
// bytes are available it CRYPTOGRAPHICALLY verifies the credential (SAID + issuer
// KEL anchoring + watcher duplicity, and holder-binding if a presentation
// signature is present). Without the driver or the credential body nothing is
// admitted: a declared field is not evidence.
func (s *CoreServer) credentialGateSatisfied(ctx context.Context, presented []interface{}, signerAID, schema, issuer string) (bool, string) {
	lastReason := "required credential not presented"
	if signerAID == "" {
		// An empty holder would switch the holder check off.
		return false, "no identity signing in to hold the credential"
	}
	for _, p := range presented {
		m, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if !sameSchema(credStr(m["schema_said"]), schema) {
			continue
		}
		if issuer != "" && credStr(m["issuer_aid"]) != issuer {
			lastReason = "credential from an unexpected issuer"
			continue
		}
		// No credential body, no pass. A declared field (a said, a status) is
		// whatever the holder chose to write, so it is never read as evidence
		// about a credential this agent could have revoked.
		acdcB64 := credStr(m["acdc_json_b64"])
		if s.KeriDriver == nil || acdcB64 == "" {
			lastReason = "credential body not presented, so it cannot be verified"
			continue
		}
		// The holder is the identity that signed in, never the holder the
		// presenter declares: the driver checks it against the credential's
		// own issuee, so a credential issued to somebody else is refused.
		verified, iss, reason := s.verifyPresentedCredentialACDC(ctx, acdcB64,
			signerAID, credStr(m["pres_said_b64"]),
			credStr(m["cesr_sig"]), credStr(m["holder_public_key"]), schemaForms(schema))
		if verified && (issuer == "" || iss == issuer) {
			return true, ""
		}
		lastReason = "credential verification failed: " + reason
	}
	return false, lastReason
}

// verifyPresentedCredentialACDC cryptographically verifies a presented ACDC via
// the KERI driver, resolving the issuer's KEL (contact KEL for a third-party
// issuer, own KEL for self-issued) and running the watcher for issuer-KEL
// duplicity. Returns (verified, issuerAID, reason). Mirrors handleVerifyCredential.
func (s *CoreServer) verifyPresentedCredentialACDC(ctx context.Context, acdcJsonB64, holderAid, presSaidB64, cesrSig, holderPubKey string, trustedSchemas []string) (bool, string, string) {
	if s.KeriDriver == nil {
		return false, "", "keri driver unavailable"
	}
	var issuerKelEvents []map[string]interface{}
	cred, err := readCredentialHere(acdcJsonB64)
	if err != nil {
		return false, "", err.Error()
	}
	issuerAid := cred.Issuer
	if issuerAid != "" {
		issuerKelEvents = s.issuerLogForVerification(issuerAid)
	}
	if issuerKelEvents == nil {
		return false, issuerAid, "issuer KEL not found"
	}
	issuance := s.issuanceLogForVerification(cred, issuerKelEvents)
	issuerKelEvents = issuance.issuerKel
	result, err := s.verifyCredentialHere(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:           acdcJsonB64,
		IssuerKelEvents:    issuerKelEvents,
		HolderAid:          holderAid,
		PresentationSaid:   presSaidB64,
		CesrSignature:      cesrSig,
		HolderPublicKey:    holderPubKey,
		TrustedSchemaSaids: trustedSchemas,
	}, cred, issuance)
	if err != nil {
		return false, issuerAid, "verify error: " + err.Error()
	}
	if !result.Verified {
		reason := "credential not verified"
		if len(result.Errors) > 0 {
			reason = strings.Join(result.Errors, "; ")
		}
		return false, issuerAid, reason
	}
	// Watcher: reject if the issuer's KEL shows duplicity (matters for third-party issuers).
	if wRes := s.runWatcherOnKel(ctx, issuerAid, issuerKelEvents, watcher.SourceCredential, "", nil); wRes != nil && wRes.Blocked {
		return false, issuerAid, "issuer KEL duplicity: " + wRes.Reason
	}
	return true, issuerAid, ""
}

func isUsableStatus(status string) bool {
	switch status {
	case "", "issued", "valid", "active":
		return true
	default:
		return false
	}
}

// presentsRequiredCredential reports whether the presented ACDCs include a
// usable credential of the required schema (and issuer, if constrained).
// NOTE: this checks the credential's declared schema/issuer/status as carried
// in the (signed) assertion. Full ACDC cryptographic verification + holder
// binding via the KERI driver is a hardening follow-up.
func presentsRequiredCredential(presented []interface{}, schemaSAID, issuerAID string) bool {
	for _, p := range presented {
		m, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if !sameSchema(credStr(m["schema_said"]), schemaSAID) {
			continue
		}
		if issuerAID != "" && credStr(m["issuer_aid"]) != issuerAID {
			continue
		}
		switch credStr(m["status"]) {
		case "", "issued", "valid", "active":
			return true
		}
	}
	return false
}

func credStr(v interface{}) string {
	s, _ := v.(string)
	return s
}

// GET /api/login/challenge/{token}/status — what happened, for the browser that
// started it.
//
// The token alone is not enough to read this, and that is the point. It travels
// in the QR code and in the callback URL, so anybody who saw a sign-in screen
// could otherwise poll here and collect the person's identifier, the fields
// they disclosed and their role, at the moment they signed in. The collector
// secret was returned once, to the browser that asked for the challenge.
func (s *CoreServer) handleChallengeStatus(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	offered := r.Header.Get("X-Collector-Secret")
	if offered == "" {
		offered = r.URL.Query().Get("collector")
	}

	bound, held := s.collectorHeld(token, offered)
	st := s.challengeStatusOf(token)
	if bound && !held {
		// Uniform: a wrong secret and an unknown token answer the same, so
		// this cannot be used to discover which sign-ins are in progress.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if st == nil {
		st = map[string]interface{}{"status": "pending"}
	}
	if !bound {
		// A challenge created before this existed, or by a path that does not
		// mint one. An unbound status is indistinguishable from a bound one, so
		// it says so.
		st["session_binding"] = "none"
	}
	jsonreply.Write(w, http.StatusOK, st)
}

// schemaForms are the identifiers a credential of one schema may carry: the
// identifier itself and, where the schema's identifier was once a placeholder,
// the other form. A credential issued before the identifier was real names the
// placeholder, and a gate set up before names it too, so neither is refused for
// the other (ADR-045, amendment of 2026-11-05).
func schemaForms(said string) []string {
	if other := schemas.Equivalent(said); other != "" {
		return []string{said, other}
	}
	return []string{said}
}

// sameSchema reports whether a presented credential's schema identifier is the
// required one, in either of its forms.
func sameSchema(presented, required string) bool {
	for _, f := range schemaForms(required) {
		if presented == f {
			return true
		}
	}
	return false
}

// collectorHeld says whether offered is the collector secret minted for the
// sign-in token (bound), and whether the offer matches it (held). A sign-in
// with no secret minted is not bound.
func (s *CoreServer) collectorHeld(token, offered string) (bound, held bool) {
	s.challengeMu.Lock()
	want, bound := s.challengeCollector[token]
	s.challengeMu.Unlock()
	if !bound {
		return false, false
	}
	got := sha256.Sum256([]byte(offered))
	return true, subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// challengeStatusOf is a copy of the sign-in's status, nil when there is none.
func (s *CoreServer) challengeStatusOf(token string) map[string]interface{} {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	st := s.challengeStatus[token]
	if st == nil {
		return nil
	}
	cp := make(map[string]interface{}, len(st))
	for k, v := range st {
		cp[k] = v
	}
	return cp
}
