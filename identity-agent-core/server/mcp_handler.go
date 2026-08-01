package server

import (
	"encoding/json"
	"io"
	"net/http"
)

// The agent exposes ONE MCP server (this handler). tools/list = capability discovery;
// tools/call = the governed invoke path (ingress -> plug-in -> egress). Every call is
// gated the same way regardless of transport: a remote caller cannot invoke a
// host-control capability, and is default-denied without scope (see sandbox.authorizeIngress).

type mcpReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpErr         `json:"error,omitempty"`
}

type mcpErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *CoreServer) handleMCP(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		jsonResponse(w, mcpResp{JSONRPC: "2.0", Error: &mcpErr{Code: -32700, Message: "parse error"}})
		return
	}
	var req mcpReq
	if err := json.Unmarshal(body, &req); err != nil {
		jsonResponse(w, mcpResp{JSONRPC: "2.0", Error: &mcpErr{Code: -32700, Message: "parse error"}})
		return
	}

	caller := s.resolveCaller(r)
	applyCallerWhy(r, &caller)

	// Verify an optional signed-request envelope (per-request signature +
	// anti-replay). Absent → no-op; present-but-invalid → reject the request.
	if err := s.verifyRequestEnvelope(r, req.Method, req.Params, &caller); err != nil {
		jsonResponse(w, mcpResp{JSONRPC: "2.0", ID: req.ID, Error: &mcpErr{Code: -32001, Message: err.Error()}})
		return
	}
	// Identity-first: an agent that proved its AID by envelope (no bearer token) picks
	// up its delegation lineage + capability ceiling from its provisioned asset here.
	s.enrichCallerFromIdentity(&caller)

	switch req.Method {
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted) // JSON-RPC notification: no response body
	case "initialize":
		jsonResponse(w, mcpResp{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]any{"name": "identity-agent-endpoint", "version": "0.1.0"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}})
	case "ping":
		jsonResponse(w, mcpResp{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})
	case "tools/list":
		jsonResponse(w, mcpResp{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"tools": s.SandboxManager.MCPToolsList(caller),
		}})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.Name == "" {
			jsonResponse(w, mcpResp{JSONRPC: "2.0", ID: req.ID, Error: &mcpErr{Code: -32602, Message: "missing tool name"}})
			return
		}
		args := []byte(p.Arguments)
		if len(args) == 0 {
			args = []byte("{}")
		}
		tr := s.SandboxManager.MCPToolsCall(r.Context(), caller, p.Name, args)
		jsonResponse(w, mcpResp{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": tr.Text}},
			"isError": tr.IsError,
		}})
	default:
		jsonResponse(w, mcpResp{JSONRPC: "2.0", ID: req.ID, Error: &mcpErr{Code: -32601, Message: "method not found: " + req.Method}})
	}
}

// handleEndpointHealth is the REST-surface skeleton's health probe. The REST surface
// is structure-only for now (the capability list + invoke routes already exist); the
// MCP server is the built-out surface. GraphQL is planned.
func (s *CoreServer) handleEndpointHealth(w http.ResponseWriter, r *http.Request) {
	n := 0
	if s.SandboxManager != nil {
		n = len(s.SandboxManager.MCPToolsList(s.resolveCaller(r)))
	}
	jsonResponse(w, map[string]any{
		"status": "ok",
		"surfaces": map[string]any{
			"mcp":               "POST /mcp",
			"rest_capabilities": "GET /capabilities · POST /capabilities/{id}/invoke",
			"graphql":           "planned",
		},
		"capabilities": n,
	})
}
