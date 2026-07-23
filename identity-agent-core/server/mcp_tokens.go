package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/sandbox"
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

// isLocalOwnerRequest: genuinely local = loopback connection AND no forwarding headers.
func isLocalOwnerRequest(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return sandbox.IsLoopbackHost(host) && !hasForwardingHeaders(r)
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
		presented := hashMCPToken(tok)
		mcpTokensMu.Lock()
		toks := t.s.loadMCPTokens()
		mcpTokensMu.Unlock()
		for _, entry := range toks {
			if subtle.ConstantTimeCompare([]byte(entry.Hash), []byte(presented)) == 1 {
				cc.Scopes = entry.Scopes
				cc.CallerAID = "token:" + entry.Name
				return cc
			}
		}
		// An invalid token is a remote caller with no scopes — not the owner.
		return cc
	}
	if isLocalOwnerRequest(r) {
		cc.Remote = false
		cc.CallerAID = "local-owner"
	}
	return cc
}

// handleMintMCPToken mints a token (local owner only). Scopes are capability ids the
// token may invoke; the plaintext token is returned once and only its hash is stored.
func (s *CoreServer) handleMintMCPToken(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "token management is local-owner only", http.StatusForbidden)
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

// handleListMCPTokens lists token names + scopes (never hashes), local owner only.
func (s *CoreServer) handleListMCPTokens(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "token management is local-owner only", http.StatusForbidden)
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
	if !isLocalOwnerRequest(r) {
		jsonError(w, "token management is local-owner only", http.StatusForbidden)
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

// handleListInvocationEvents is the Activity read: the signed invocation log, newest
// first — who did what, when, under whose authority. Local owner only for now; the
// governed read for other callers arrives with ACDC resolution.
func (s *CoreServer) handleListInvocationEvents(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "activity is local-owner only", http.StatusForbidden)
		return
	}
	if s.SandboxManager == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	events, err := s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
		CapabilityID:  q.Get("capability_id"),
		CorrelationID: q.Get("correlation_id"),
		CallerAID:     q.Get("caller_aid"),
	})
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"events": events})
}
