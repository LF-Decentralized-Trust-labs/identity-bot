package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/drivers"
	"identity-agent-core/sandbox"
	"identity-agent-core/store"
)

// MCP access tokens are the first rung of the endpoint's auth ladder: a positive
// credential a remote environment presents to the agent's endpoint, minted and revocable by the
// local owner, carrying granted capability scopes. Rung 2 (ACDC presentation) replaces
// this behind the same CallerResolver seam. Tokens are stored hashed; the plaintext is
// shown once at mint.
//
// Trust rule: connection origin is NEVER identity. A tunnel daemon (cloudflared,
// ngrok) connects from localhost, so a loopback RemoteAddr does not imply the local
// owner — any request carrying a forwarding header is treated as remote, and remote
// callers get scopes only from a positive credential.

type mcpToken struct {
	Name      string    `json:"name"`
	Hash      string    `json:"hash"` // sha256 hex of the plaintext token
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	// AgentAID + DelegatorAID bind a token to a provisioned ai_agent asset's
	// delegated identity. When set, the caller resolves to the agent's
	// real KERI AID and its lineage to the owner root, instead of "token:<name>".
	AgentAID     string `json:"agent_aid,omitempty"`
	DelegatorAID string `json:"delegator_aid,omitempty"`
	AssetID      string `json:"asset_id,omitempty"`
	// GrantSAID is the capability-grant credential (an ACDC the owner issued to
	// this agent) whose verified attributes are the authoritative capability
	// ceiling. When present and the KERI driver is available, authority is
	// credential-proven at invoke time; otherwise the resolver falls back to
	// the Scopes list above (the stored ceiling).
	GrantSAID string `json:"grant_said,omitempty"`
}

var mcpTokensMu sync.Mutex

func (s *CoreServer) mcpTokensPath() string {
	return filepath.Join(s.DataDir, "mcp_tokens.json")
}

func (s *CoreServer) loadMCPTokens() []mcpToken {
	data, err := os.ReadFile(s.mcpTokensPath())
	if err != nil {
		return nil
	}
	var toks []mcpToken
	if json.Unmarshal(data, &toks) != nil {
		return nil
	}
	return toks
}

func (s *CoreServer) saveMCPTokens(toks []mcpToken) error {
	data, err := json.MarshalIndent(toks, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.mcpTokensPath(), data, 0600)
}

func hashMCPToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// hasForwardingHeaders reports whether a request arrived through a tunnel/proxy —
// in which case a loopback RemoteAddr must NOT be trusted as the local owner.
func hasForwardingHeaders(r *http.Request) bool {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "Cf-Connecting-Ip", "True-Client-Ip", "Forwarded"} {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// isBrowserOriginated reports whether this request was issued by a web page
// rather than by a program running on this machine.
//
// A page loaded from anywhere reaches 127.0.0.1 as a loopback connection with
// no forwarding headers, so by the old test every website in the world was the
// owner of this Identity Agent. Visiting a page was enough to read the roster, the
// invitation secrets and the identity.
//
// What separates the two is that a browser describes itself and cannot be
// talked out of it. Origin and the Sec-Fetch-* family are forbidden header
// names: they are set by the browser, and page script cannot change or remove
// them. A native client on this machine sends none of them.
//
// This does not defend against another program on the machine — that program
// already has the user's files and does not need the API. The browser is the
// caller this closes.
func isBrowserOriginated(r *http.Request) bool {
	if r.Header.Get("Origin") != "" {
		return true
	}
	// Sec-Fetch-Site is "none" for a request the user typed into the address
	// bar; anything else is a page acting on its own initiative.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "none" {
		return true
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode == "cors" || mode == "no-cors" {
		return true
	}
	return r.Header.Get("Sec-Fetch-Dest") != ""
}

// isLocalOwnerRequest: genuinely local = loopback connection, no forwarding
// headers, and not issued by a web page.
func isLocalOwnerRequest(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return sandbox.IsLoopbackHost(host) &&
		!hasForwardingHeaders(r) &&
		!isBrowserOriginated(r)
}

// requestCorrelationID propagates the caller's correlation id, or mints one at this
// origin — minted at the origin request, carried through every hop.
func requestCorrelationID(r *http.Request) string {
	if cid := r.Header.Get("X-Correlation-Id"); cid != "" {
		return cid
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// bearerFrom extracts the presented token (Authorization: Bearer ... or X-IA-Token).
func bearerFrom(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return r.Header.Get("X-IA-Token")
}

// tokenAwareResolver is the default CallerResolver: a valid MCP token grants its
// scopes (as a remote caller); a genuinely local request is the owner; everything
// else is remote with no scopes (default-deny at the gateway).
type tokenAwareResolver struct{ s *CoreServer }

func (t tokenAwareResolver) Resolve(r *http.Request) sandbox.CallerContext {
	cc := sandbox.CallerContext{
		Remote:        true,
		CorrelationID: requestCorrelationID(r),
		Transport:     "mcp",
	}
	if tok := bearerFrom(r); tok != "" {
		cc.AuthLevel = "bearer" // upgraded to "signed_request" if an envelope verifies
		presented := hashMCPToken(tok)
		mcpTokensMu.Lock()
		toks := t.s.loadMCPTokens()
		mcpTokensMu.Unlock()
		for _, entry := range toks {
			if subtle.ConstantTimeCompare([]byte(entry.Hash), []byte(presented)) == 1 {
				cc.Scopes = entry.Scopes
				if entry.AgentAID != "" {
					// A token bound to a provisioned agent identity: the caller IS
					// that delegated AID, with its lineage to the owner root.
					cc.CallerAID = entry.AgentAID
					cc.DelegationChain = []string{entry.AgentAID}
					if entry.DelegatorAID != "" {
						cc.DelegationChain = append(cc.DelegationChain, entry.DelegatorAID)
					}
					// Credential-proven authority: when the agent holds a capability
					// grant (an ACDC the owner issued to it) and the KERI driver is
					// available, verify it and derive the ceiling FROM the credential
					// rather than trusting the stored scope list. A revoked, missing,
					// tampered, or wrong-issuer grant yields no scopes (default-deny).
					// Driverless builds fall back to the stored ceiling above.
					t.s.applyGrantScopes(entry, &cc)
				} else {
					cc.CallerAID = "token:" + entry.Name
				}
				return cc
			}
		}
		// An invalid token is a remote caller with no scopes — not the owner.
		return cc
	}

	// A machine this identity enrolled, signing as itself.
	//
	// This is the seam caller_resolver.go describes and left empty — "when
	// delegated-identity resolution is implemented it is injected via
	// CoreServer.CallerResolver and fills the AID + granted scopes". The
	// enrolment ceremony already anchors a delegated inception over a key the
	// machine generated and records that key, so the agent has everything it
	// needs to recognise the machine again. Nothing was asking.
	//
	// IT IDENTIFIES AND GRANTS NOTHING, and that separation is the whole point
	// of doing it in this order. Scopes stay empty, so this changes what the
	// agent KNOWS about a caller and not one thing about what any caller may
	// reach: authorize() gives a scoped route to anyone holding any scope, so
	// filling them here would quietly hand an enrolled machine the capability
	// surface on the way past. What a controller may do is a decision, and it
	// is a separate one from being able to tell who is asking.
	//
	// What it does buy immediately is an audit record that names the machine
	// and its lineage to the owner, where there was previously a remote caller
	// with no name at all.
	if a, err := t.s.identifyAssetFromSignature(r); err == nil && a != nil {
		cc.CallerAID = a.PairwiseAID
		cc.AuthLevel = "signed_request"
		cc.EnvelopeVerified = true
		cc.Transport = "signed"
		cc.DelegationChain = []string{a.PairwiseAID}
		if a.DelegatorAID != "" {
			cc.DelegationChain = append(cc.DelegationChain, a.DelegatorAID)
		}
		return cc
	}

	if isLocalOwnerRequest(r) {
		cc.Remote = false
		cc.CallerAID = "local-owner"
	}
	return cc
}

// handleMintMCPToken mints a token (owner only). Scopes are capability ids the
// token may invoke; the plaintext token is returned once and only its hash is stored.
func (s *CoreServer) handleMintMCPToken(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "token management is for the owner of this agent", http.StatusForbidden)
		return
	}
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	if len(req.Scopes) == 0 {
		jsonError(w, "scopes is required (capability ids this token may invoke)", http.StatusBadRequest)
		return
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	plaintext := "iamcp_" + base64.RawURLEncoding.EncodeToString(raw)

	mcpTokensMu.Lock()
	defer mcpTokensMu.Unlock()
	toks := s.loadMCPTokens()
	for _, t := range toks {
		if t.Name == req.Name {
			jsonError(w, "a token with that name already exists", http.StatusConflict)
			return
		}
	}
	toks = append(toks, mcpToken{
		Name:      req.Name,
		Hash:      hashMCPToken(plaintext),
		Scopes:    req.Scopes,
		CreatedAt: time.Now().UTC(),
	})
	if err := s.saveMCPTokens(toks); err != nil {
		jsonError(w, "failed to persist token", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{
		"name":   req.Name,
		"token":  plaintext,
		"scopes": req.Scopes,
		"note":   "store this token now; only its hash is kept",
	})
}

// handleListMCPTokens lists token names + scopes (never hashes), owner only.
func (s *CoreServer) handleListMCPTokens(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "token management is for the owner of this agent", http.StatusForbidden)
		return
	}
	mcpTokensMu.Lock()
	toks := s.loadMCPTokens()
	mcpTokensMu.Unlock()
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, map[string]any{"name": t.Name, "scopes": t.Scopes, "created_at": t.CreatedAt})
	}
	jsonResponse(w, map[string]any{"tokens": out})
}

// handleRevokeMCPToken deletes a token by name, local owner only.
func (s *CoreServer) handleRevokeMCPToken(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "token management is for the owner of this agent", http.StatusForbidden)
		return
	}
	name := chi.URLParam(r, "name")
	mcpTokensMu.Lock()
	defer mcpTokensMu.Unlock()
	toks := s.loadMCPTokens()
	kept := toks[:0]
	removed := false
	for _, t := range toks {
		if t.Name == name {
			removed = true
			continue
		}
		kept = append(kept, t)
	}
	if !removed {
		jsonError(w, "no such token", http.StatusNotFound)
		return
	}
	if err := s.saveMCPTokens(kept); err != nil {
		jsonError(w, "failed to persist revocation", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"revoked": name})
}

// applyGrantScopes derives an agent's capability ceiling from its verified
// capability-grant credential — credential-proven authority. On success
// cc.Scopes becomes the credential's capabilities and cc.GrantSAID records the
// grant — authority is credential-proven. If a grant is present but fails
// verification (revoked, missing, tampered, or from the wrong issuer), cc.Scopes
// is cleared so the gateway default-denies. With no grant or no KERI driver it
// leaves the stored ceiling (already set by the caller) untouched — driverless
// builds keep working on the increment-1 behaviour.
func (s *CoreServer) applyGrantScopes(entry mcpToken, cc *sandbox.CallerContext) {
	if entry.GrantSAID == "" || s.KeriDriver == nil {
		return // no credential / no driver → the stored ceiling governs
	}
	rec, err := s.DataStore.GetCredential(entry.GrantSAID)
	if err != nil || rec == nil {
		// The token references a grant that no longer exists — treat as revoked.
		log.Printf("[mcp] agent %s grant %s not found — denying", entry.AgentAID, entry.GrantSAID)
		cc.Scopes = nil
		return
	}
	if !isUsableStatus(rec.Status) {
		// The owner revoked (or expired) the grant — hard deny.
		log.Printf("[mcp] agent %s grant %s status=%q — denying", entry.AgentAID, entry.GrantSAID, rec.Status)
		cc.Scopes = nil
		return
	}
	if !s.grantCredentialValid(rec, entry) {
		// The grant exists and is not revoked, but did not cryptographically verify.
		// Fail closed — deny — rather than authorize on the stored ceiling, which
		// would be an authority state that looks legitimate but is not proven. A
		// legitimately-provisioned agent's grant always verifies (its owner-root
		// anchor is persisted at provisioning); a failure here is a real problem
		// that must surface as a denial, not a silent fallback.
		cc.Scopes = nil
		return
	}
	// Credential-proven: derive the ceiling and any resource constraints from the
	// verified grant, and record it.
	if caps := capabilitiesFromACDC(rec.AcdcJson); len(caps) > 0 {
		cc.Scopes = caps // source of truth = the verified credential
	}
	cc.ResourceConstraints = resourceConstraintsFromACDC(rec.AcdcJson)
	cc.GrantSAID = rec.SAID
}

// resourceConstraintsFromACDC extracts the optional per-capability resource
// constraints (capabilityID -> {argKey: [allowedValues]}) from a capability-grant
// ACDC's attribute block. Returns nil when absent.
func resourceConstraintsFromACDC(acdcJsonB64 string) map[string]interface{} {
	raw, err := base64.StdEncoding.DecodeString(acdcJsonB64)
	if err != nil {
		return nil
	}
	var body map[string]interface{}
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	get := func(m map[string]interface{}) map[string]interface{} {
		if rc, ok := m["resource_constraints"].(map[string]interface{}); ok {
			return rc
		}
		return nil
	}
	if rc := get(body); rc != nil {
		return rc
	}
	if attrs, ok := body["a"].(map[string]interface{}); ok {
		return get(attrs)
	}
	return nil
}

// grantCredentialValid cryptographically verifies a capability-grant ACDC against
// the issuer's authoritative KEL, fetched live from the KERI driver. (The store's
// copy of the owner-root KEL can lag the anchoring event, so the driver's KEL —
// not the store — is the source of truth for a self-issued grant.) Verification
// confirms the ACDC is anchored in the issuer's KEL, binding it to the owner root;
// the holder must be the agent. Returns false on any failure.
func (s *CoreServer) grantCredentialValid(rec *store.CredentialRecord, entry mcpToken) bool {
	issuer := entry.DelegatorAID
	if issuer == "" {
		issuer = rec.IssuerAID
	}
	kel, err := s.KeriDriver.GetKel(issuer)
	if err != nil || kel == nil || len(kel.KEL) == 0 {
		log.Printf("[mcp] grant %s: issuer KEL unavailable: %v", rec.SAID, err)
		return false
	}
	result, err := s.KeriDriver.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:           rec.AcdcJson,
		IssuerKelEvents:    kel.KEL,
		HolderAid:          entry.AgentAID,
		TrustedSchemaSaids: []string{capabilityGrantSchemaSAID},
	})
	if err != nil || result == nil {
		reason := "not verified"
		if err != nil {
			reason = err.Error()
		}
		log.Printf("[mcp] grant %s failed verification: %s — denying", rec.SAID, reason)
		return false
	}
	// Require the structural, issuer, schema, and revocation checks. The holder
	// presentation-binding check (presentation_sig_valid) is intentionally NOT
	// required: the agent authenticates via its bound token, not by presenting a
	// signed ACDC, and holder_matches_subject already binds the grant to this agent.
	required := []string{
		"said_integrity", "issuer_in_kel", "kel_chain_valid",
		"schema_trusted", "not_revoked", "holder_matches_subject", "credential_anchored",
	}
	for _, k := range required {
		if ok, _ := result.Checks[k].(bool); !ok {
			log.Printf("[mcp] grant %s failed verification check %q (errors: %v) — denying", rec.SAID, k, result.Errors)
			return false
		}
	}
	return true
}

// capabilitiesFromACDC extracts the granted capability ids from a capability-grant
// ACDC (base64-encoded JSON). ACDC claims live in the attribute block "a"; a flat
// top-level "capabilities" is accepted as a fallback.
func capabilitiesFromACDC(acdcJsonB64 string) []string {
	raw, err := base64.StdEncoding.DecodeString(acdcJsonB64)
	if err != nil {
		return nil
	}
	var body map[string]interface{}
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	list, ok := body["capabilities"].([]interface{})
	if !ok {
		if attrs, ok2 := body["a"].(map[string]interface{}); ok2 {
			list, _ = attrs["capabilities"].([]interface{})
		}
	}
	out := make([]string, 0, len(list))
	for _, c := range list {
		if str, ok := c.(string); ok && str != "" {
			out = append(out, str)
		}
	}
	return out
}
