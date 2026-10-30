package aiagents

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/drivers"
	"identity-agent-core/permission"
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
	// MadeByController is the machine that minted this token, when one did
	// rather than the owner. Recorded so revoking that machine can list what
	// it made: a token outlives the grant of the controller that minted it.
	MadeByController string `json:"made_by_controller,omitempty"`
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
	// GrantPending is a grant that only the device holding the identity's key
	// can issue. Until it is issued the token may do nothing.
	GrantPending bool `json:"grant_pending,omitempty"`
}

var mcpTokensMu sync.Mutex

func (s *aiAgents) mcpTokensPath() string {
	return filepath.Join(s.DataDir, "mcp_tokens.json")
}

func (s *aiAgents) loadMCPTokens() []mcpToken {
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

func (s *aiAgents) saveMCPTokens(toks []mcpToken) error {
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

// handleMintMCPToken mints a token. Scopes are capability ids the
// token may invoke; the plaintext token is returned once and only its hash is stored.
func (s *aiAgents) handleMintMCPToken(w http.ResponseWriter, r *http.Request) {
	// App operation — authorized by the router-wide authorize gate (owner or the
	// owner's authorized controller). The token is bounded by its capability grant,
	// checked at invoke time, so minting it is not a root-of-trust operation.
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		helpers.JSONError(w, "name is required", http.StatusBadRequest)
		return
	}
	if len(req.Scopes) == 0 {
		helpers.JSONError(w, "scopes is required (capability ids this token may invoke)", http.StatusBadRequest)
		return
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		helpers.JSONError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	plaintext := "iamcp_" + base64.RawURLEncoding.EncodeToString(raw)

	mcpTokensMu.Lock()
	defer mcpTokensMu.Unlock()
	toks := s.loadMCPTokens()
	for _, t := range toks {
		if t.Name == req.Name {
			helpers.JSONError(w, "a token with that name already exists", http.StatusConflict)
			return
		}
	}
	toks = append(toks, mcpToken{
		Name:      req.Name,
		Hash:      hashMCPToken(plaintext),
		Scopes:    req.Scopes,
		CreatedAt: time.Now().UTC(),

		MadeByController: helpers.MadeByController(r),
	})
	if err := s.saveMCPTokens(toks); err != nil {
		helpers.JSONError(w, "failed to persist token", http.StatusInternalServerError)
		return
	}
	helpers.JSONResponse(w, map[string]any{
		"name":   req.Name,
		"token":  plaintext,
		"scopes": req.Scopes,
		"note":   "store this token now; only its hash is kept",
	})
}

// handleListMCPTokens lists token names + scopes (never hashes).
func (s *aiAgents) handleListMCPTokens(w http.ResponseWriter, r *http.Request) {
	// App operation — authorized by the router-wide authorize gate (owner or the
	// owner's authorized controller); the token list is not owner-only.
	mcpTokensMu.Lock()
	toks := s.loadMCPTokens()
	mcpTokensMu.Unlock()
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		entry := map[string]any{"name": t.Name, "scopes": t.Scopes, "created_at": t.CreatedAt}
		if t.MadeByController != "" {
			entry["made_by_controller"] = t.MadeByController
		}
		out = append(out, entry)
	}
	helpers.JSONResponse(w, map[string]any{"tokens": out})
}

// handleRevokeMCPToken deletes a token by name.
func (s *aiAgents) handleRevokeMCPToken(w http.ResponseWriter, r *http.Request) {
	// App operation — authorized by the router-wide authorize gate (owner or the
	// owner's authorized controller); revoking a token is not a root-of-trust operation.
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
		helpers.JSONError(w, "no such token", http.StatusNotFound)
		return
	}
	if err := s.saveMCPTokens(kept); err != nil {
		helpers.JSONError(w, "failed to persist revocation", http.StatusInternalServerError)
		return
	}
	helpers.JSONResponse(w, map[string]any{"revoked": name})
}

// applyGrantScopes derives an agent's capability ceiling from its verified
// capability-grant credential — credential-proven authority. On success
// cc.Scopes becomes the credential's capabilities and cc.GrantSAID records the
// grant — authority is credential-proven. If a grant is present but fails
// verification (revoked, missing, tampered, or from the wrong issuer), cc.Scopes
// is cleared so the gateway default-denies. With no grant or no KERI driver it
// leaves the stored ceiling (already set by the caller) untouched — driverless
// builds keep working on the increment-1 behaviour.
func (s *aiAgents) applyGrantScopes(entry mcpToken, cc *permission.CallerContext) {
	// A revoked AI agent may do nothing, whatever its grant credential still
	// says while its withdrawal is being written (ADR-056).
	if entry.AssetID != "" {
		if _, revoked := s.revokedAIAgents().Get(entry.AssetID); revoked {
			cc.Scopes = nil
			cc.NoScopesBecause = "this AI agent was revoked"
			return
		}
	}
	if s.KeriDriver == nil {
		return // a build with no engine has no grants: the stored ceiling governs
	}
	if entry.GrantSAID == "" {
		// An AI agent's token with no grant, where grants can be issued, is
		// one whose grant was never issued: it may do nothing.
		if entry.AgentAID != "" {
			log.Printf("[mcp] agent %s holds no grant — denying", entry.AgentAID)
			cc.Scopes = nil
			cc.NoScopesBecause = "this AI agent is " + helpers.AwaitingPhrase(entry.GrantPending)
		}
		return
	}
	rec, err := s.DataStore.GetCredential(entry.GrantSAID)
	if err != nil || rec == nil {
		// The token references a grant that no longer exists — treat as revoked.
		log.Printf("[mcp] agent %s grant %s not found — denying", entry.AgentAID, entry.GrantSAID)
		cc.Scopes = nil
		return
	}
	if !helpers.IsUsableStatus(rec.Status) {
		// The owner revoked (or expired) the grant — hard deny.
		log.Printf("[mcp] agent %s grant %s status=%q — denying", entry.AgentAID, entry.GrantSAID, rec.Status)
		cc.Scopes = nil
		if grantLapsed(*rec) {
			cc.NoScopesBecause = "this AI agent's grant has expired"
		}
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
		if grantLapsed(*rec) {
			cc.NoScopesBecause = "this AI agent's grant has expired"
		}
		return
	}
	// Credential-proven: derive the ceiling and any resource constraints from the
	// verified grant, and record it.
	// Source of truth = the verified credential, including when it grants
	// nothing: an empty list is an agent stripped of everything, not a cue to
	// fall back to whatever the token remembered.
	//
	// Never wider than what the token itself was given, either: if the two ever
	// disagree, the narrower answer stands.
	cc.Scopes = intersectScopes(capabilitiesFromACDC(rec.AcdcJson), entry.Scopes)
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
// the issuer's key log as it is stored and published, signed, up to and
// including the event that issued it. Later events say nothing about whether
// this grant was issued, so a later event that cannot be verified does not
// withdraw it; revocation is checked separately. The issuer must be the AI
// agent's delegator, and the holder the AI agent. Returns false on any failure.
func (s *aiAgents) grantCredentialValid(rec *store.CredentialRecord, entry mcpToken) bool {
	if s.IssuedUnderFirstVersionTooLate(rec) {
		log.Printf("[mcp] grant %s names nobody who authorised it, though it was issued after grants began to — denying", rec.SAID)
		return false
	}
	issuer := entry.DelegatorAID
	if issuer == "" || rec.IssuerAID != issuer {
		// A grant counts only from the identity that delegated the AI agent.
		// Anybody can issue a credential naming an AI agent's identifier.
		log.Printf("[mcp] grant %s was issued by %q, not by the AI agent's delegator %q — denying",
			rec.SAID, rec.IssuerAID, issuer)
		return false
	}
	// The issuer's log as it is stored and published — with each event's bytes
	// and signature — rather than the engine's working copy, which holds neither
	// signature and so could only ever be reported as an unproven chain.
	full, err := s.StoredKelForVerifying(issuer)
	if err != nil || len(full) == 0 {
		log.Printf("[mcp] grant %s: issuer KEL unavailable: %v", rec.SAID, err)
		return false
	}
	// Anchored: the issuer's own log carries the event that issued it, and that
	// event's seal names this grant's issuance. A grant whose issuance is not in
	// the issuer's history was not issued by it.
	kel, anchored := kelUpToIssuance(full, rec.IxnSAID, rec.IssSAID)
	if !anchored {
		log.Printf("[mcp] grant %s: its issuance %q is not anchored in the issuer's key log — denying", rec.SAID, rec.IxnSAID)
		return false
	}
	result, err := s.KeriDriver.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:           rec.AcdcJson,
		IssuerKelEvents:    kel,
		HolderAid:          entry.AgentAID,
		TrustedSchemaSaids: helpers.CapabilityGrantSchemaSAIDs(),
	})
	if err != nil || result == nil {
		reason := "not verified"
		if err != nil {
			reason = err.Error()
		}
		log.Printf("[mcp] grant %s failed verification: %s — denying", rec.SAID, reason)
		return false
	}
	// Every one of these must have been checked AND passed. A check the engine did
	// not run is absent, and absent is a failure: the list names what this gate
	// relies on, so an engine that stopped reporting one cannot pass by silence.
	//
	// Not required: proof that the holder presented it. The agent authenticates
	// with its bound token rather than by presenting the credential, and "holder"
	// already binds the grant to this agent.
	for _, k := range []string{"structure", "schema_accepted", "holder", "issuer_kel"} {
		if ok, _ := result.Checks[k].(bool); !ok {
			log.Printf("[mcp] grant %s failed verification check %q (errors: %v) — denying", rec.SAID, k, result.Errors)
			return false
		}
	}
	// Revocation. No registry log is handed to the engine here, so it reports
	// nothing, and the answer is this identity's own record of what it revoked —
	// authoritative here, because this identity is the issuer, and the caller has
	// already refused a grant whose record says revoked. The check below acts
	// only if a log is ever supplied.
	if v, reported := result.Checks["not_revoked"]; reported && v != nil {
		if ok, _ := v.(bool); !ok {
			log.Printf("[mcp] grant %s is revoked in its registry — denying", rec.SAID)
			return false
		}
	}
	if lapsed, when := grantHasLapsed(rec.AcdcJson, time.Now()); lapsed {
		log.Printf("[mcp] grant %s lapsed at %s — denying", rec.SAID, when)
		return false
	}
	return true
}

func intersectScopes(granted, held []string) []string {
	have := map[string]bool{}
	for _, h := range held {
		have[h] = true
	}
	out := make([]string, 0, len(granted))
	for _, g := range granted {
		if have[g] {
			out = append(out, g)
		}
	}
	return out
}

// kelUpToIssuance is the issuer's log up to and including the event that
// anchored a credential's issuance, and whether that event exists and its seal
// names the issuance event.
func kelUpToIssuance(kel []map[string]interface{}, anchorSAID, issSAID string) ([]map[string]interface{}, bool) {
	if anchorSAID == "" {
		return nil, false
	}
	for i, ev := range kel {
		if d, _ := ev["d"].(string); d != anchorSAID {
			continue
		}
		if issSAID != "" && !sealNames(ev, issSAID) {
			return nil, false
		}
		return kel[:i+1], true
	}
	return nil, false
}

func sealNames(ev map[string]interface{}, said string) bool {
	seals, _ := ev["a"].([]interface{})
	for _, raw := range seals {
		if seal, _ := raw.(map[string]interface{}); seal["d"] == said {
			return true
		}
	}
	return false
}

// grantHasLapsed reports whether a grant's valid_until is past. A grant without
// one holds until revoked; one whose valid_until cannot be read has lapsed, since
// an unreadable limit must not become no limit.
func grantHasLapsed(acdcJsonB64 string, now time.Time) (bool, string) {
	raw, err := base64.StdEncoding.DecodeString(acdcJsonB64)
	if err != nil {
		return true, "an unreadable credential"
	}
	var body struct {
		A map[string]interface{} `json:"a"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return true, "an unreadable credential"
	}
	v, present := body.A["valid_until"]
	if !present {
		return false, ""
	}
	str, _ := v.(string)
	until, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return true, fmt.Sprintf("an unreadable time %q", str)
	}
	return !now.Before(until), str
}

// capabilitiesFromACDC extracts the granted capability ids from a capability-grant
// ACDC (base64-encoded JSON), from its attribute block "a".
func capabilitiesFromACDC(acdcJsonB64 string) []string {
	raw, err := base64.StdEncoding.DecodeString(acdcJsonB64)
	if err != nil {
		return nil
	}
	var body map[string]interface{}
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	// Only the attribute block. The schema accepts nothing at the top level
	// besides the credential's own fields, so a "capabilities" found there is
	// not part of any grant this software issues.
	attrs, _ := body["a"].(map[string]interface{})
	list, _ := attrs["capabilities"].([]interface{})
	out := make([]string, 0, len(list))
	for _, c := range list {
		if str, ok := c.(string); ok && str != "" {
			out = append(out, str)
		}
	}
	return out
}

// grantLapsed reports whether a grant ended by lapsing rather than being
// withdrawn: marked expired, or past the end it states.
func grantLapsed(rec store.CredentialRecord) bool {
	if rec.Status == "expired" {
		return true
	}
	if rec.ExpiryDate == "" {
		return false
	}
	end, err := time.Parse(time.RFC3339, rec.ExpiryDate)
	return err == nil && !end.After(time.Now())
}

// agentGrantLapsed reports whether an AI agent's newest grant has lapsed.
func (s *aiAgents) agentGrantLapsed(aid string) bool {
	held := s.GrantsHeldBy(aid, false)
	if len(held) == 0 {
		return false
	}
	newest := held[0]
	for _, c := range held[1:] {
		if helpers.IssuedAt(c).After(helpers.IssuedAt(newest)) {
			newest = c
		}
	}
	return grantLapsed(newest)
}

// callerFromToken is who presented tok, when it is a token minted here: a
// token bound to an AI agent speaks as that AI agent, any other as the token.
// cc is the caller as far as the core knows it.
func (s *aiAgents) callerFromToken(tok string, cc permission.CallerContext) (permission.CallerContext, bool) {
	presented := hashMCPToken(tok)
	mcpTokensMu.Lock()
	toks := s.loadMCPTokens()
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
				s.applyGrantScopes(entry, &cc)
			} else {
				cc.CallerAID = "token:" + entry.Name
			}
			return cc, true
		}
	}
	return cc, false
}
