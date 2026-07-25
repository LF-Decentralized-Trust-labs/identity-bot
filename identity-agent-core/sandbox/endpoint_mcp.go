package sandbox

import (
	"context"
	"encoding/json"
	"log"
)

// MCPTool is the tool projection of a provided capability for an MCP tools/list.
// (The JSON-RPC framing lives in the server layer; this is just the data.)
type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ExecuteToolName is the universal invoke meta-tool: any capability (plug-in or
// registry-native) is invocable as execute{capability_id, args}. The flat per-capability
// projection stays alongside it while the catalog is small; at scale the flat list
// retracts and the meta-tools remain, keeping a caller's context cost constant.
const ExecuteToolName = "execute"

// SearchToolName finds capabilities by text + filters, returning ranked summaries
// (never full schemas) filtered to the caller's entitlements.
const SearchToolName = "search"

// DescribeToolName serves one capability's full record — the only place full input
// schemas and auth requirements are served, keeping search results context-cheap.
const DescribeToolName = "describe"

// MCPToolsList projects the agent's capabilities (plug-in-provided + registry-native)
// as MCP tools — the tools/list side of the agent's single MCP server. The flat
// per-capability projections are filtered to the caller's entitlements through the
// SAME Authorizer that governs execute/search: discovery never reveals a capability
// the caller could not invoke. The meta-tools (execute/search/describe) are always
// listed — they are the discovery surface itself and each self-gates on invocation.
func (m *Manager) MCPToolsList(caller CallerContext) []MCPTool {
	auth := m.authz()
	ctx := context.Background()
	entitled := func(capDef ProvidedCapability) bool {
		return auth.AuthorizeIngress(ctx, caller, capDef) == nil
	}

	caps := m.ProvidedCapabilities()
	tools := make([]MCPTool, 0, len(caps)+3)
	for _, c := range caps {
		// The Authorizer decides on a ProvidedCapability; the id + host-control class
		// fully determine the structural decision (and match the ACDC-scope key when
		// the full gateway lands).
		if !entitled(ProvidedCapability{ID: c.ID, Name: c.Name, HostControl: c.HostControl}) {
			continue
		}
		desc := c.Name
		if c.Description != "" {
			desc = c.Name + " — " + c.Description
		}
		if c.RequestContract != "" {
			desc += " (request: " + c.RequestContract + ")"
		}
		if c.HostControl {
			desc += " [host-control: local owner only]"
		}
		tools = append(tools, MCPTool{
			Name:        c.ID,
			Description: desc,
			// Permissive object schema; each capability's request contract defines its
			// actual arguments and is named in the description.
			InputSchema: map[string]any{"type": "object"},
		})
	}
	// Registry-native records carry a real input schema.
	if m.store != nil {
		recs, err := m.store.ListCapabilityRecords()
		if err != nil {
			log.Printf("[registry] list for tools/list: %v", err)
		}
		for _, r := range recs {
			if !entitled(r.asProvidedCapability()) {
				continue
			}
			desc := r.Name
			if r.Description != "" {
				desc = r.Name + " — " + r.Description
			}
			desc += " [governed " + r.ExecutorType + "]"
			schema := map[string]any{"type": "object"}
			if len(r.InputSchema) > 0 {
				var s map[string]any
				if json.Unmarshal(r.InputSchema, &s) == nil {
					schema = s
				}
			}
			tools = append(tools, MCPTool{Name: r.ID, Description: desc, InputSchema: schema})
		}
	}
	tools = append(tools, MCPTool{
		Name:        ExecuteToolName,
		Description: "Execute a governed capability by id. Every call is authorized by the Governance Gateway and written to the signed invocation log.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"capability_id": map[string]any{"type": "string", "description": "the capability to invoke (see search/describe)"},
				"args":          map[string]any{"type": "object", "description": "arguments per the capability's input schema (see describe)"},
			},
			"required": []string{"capability_id"},
		},
	})
	tools = append(tools, MCPTool{
		Name:        SearchToolName,
		Description: "Find capabilities. Returns ranked summaries (id, name, description — no schemas), filtered to what you are entitled to invoke. Use describe for a capability's full record.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query":         map[string]any{"type": "string", "description": "free-text match against id, name, and description; omit to browse by filters"},
				"domain":        map[string]any{"type": "string", "description": "exact domain filter (e.g. infrastructure)"},
				"executor_type": map[string]any{"type": "string", "description": "exact executor filter: internal_api | external_api | ai_agent | host_control | plugin"},
				"limit":         map[string]any{"type": "integer", "description": "max results (default 20, cap 50)"},
			},
		},
	})
	tools = append(tools, MCPTool{
		Name:        DescribeToolName,
		Description: "Full record for one capability: input schema, auth requirements, and how to invoke it with execute.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"capability_id": map[string]any{"type": "string", "description": "the capability to describe (from search)"},
			},
			"required": []string{"capability_id"},
		},
	})
	return tools
}

// MCPToolResult is the result of an MCP tools/call.
type MCPToolResult struct {
	Text    string
	IsError bool
}

// MCPToolsCall routes an MCP tools/call through the governed invoke path (ingress ->
// executor -> egress). A governance denial or capability error becomes an error
// tool-result (IsError=true) rather than a transport failure — the MCP client sees it
// as the tool's output, which is the protocol-correct shape for an execution error.
func (m *Manager) MCPToolsCall(ctx context.Context, caller CallerContext, name string, args []byte) MCPToolResult {
	if name == ExecuteToolName {
		var p struct {
			CapabilityID string          `json:"capability_id"`
			Args         json.RawMessage `json:"args"`
		}
		if err := json.Unmarshal(args, &p); err != nil || p.CapabilityID == "" {
			return MCPToolResult{Text: "execute requires {\"capability_id\": ..., \"args\": {...}}", IsError: true}
		}
		inner := []byte(p.Args)
		if len(inner) == 0 {
			inner = []byte("{}")
		}
		res, err := m.InvokeCapability(ctx, caller, p.CapabilityID, inner)
		if err != nil {
			return MCPToolResult{Text: err.Error(), IsError: true}
		}
		wrapped, _ := json.Marshal(map[string]any{
			"capability_id":  res.CapabilityID,
			"status":         res.Status,
			"correlation_id": caller.CorrelationID,
			"audit_event_id": res.AuditEventID,
			"body":           json.RawMessage(normalizeJSONBody(res.Body)),
		})
		return MCPToolResult{Text: string(wrapped), IsError: res.Status >= 400}
	}
	if name == SearchToolName {
		var q SearchQuery
		if len(args) > 0 {
			if err := json.Unmarshal(args, &q); err != nil {
				return MCPToolResult{Text: "search takes {\"query\": ..., \"domain\": ..., \"executor_type\": ..., \"limit\": ...}", IsError: true}
			}
		}
		results := m.SearchCapabilities(ctx, caller, q)
		out, _ := json.Marshal(map[string]any{"capabilities": results, "count": len(results)})
		return MCPToolResult{Text: string(out)}
	}
	if name == DescribeToolName {
		var p struct {
			CapabilityID string `json:"capability_id"`
		}
		if err := json.Unmarshal(args, &p); err != nil || p.CapabilityID == "" {
			return MCPToolResult{Text: "describe requires {\"capability_id\": ...}", IsError: true}
		}
		detail, err := m.DescribeCapability(ctx, caller, p.CapabilityID)
		if err != nil {
			return MCPToolResult{Text: err.Error(), IsError: true}
		}
		out, _ := json.Marshal(detail)
		return MCPToolResult{Text: string(out)}
	}
	res, err := m.InvokeCapability(ctx, caller, name, args)
	if err != nil {
		return MCPToolResult{Text: err.Error(), IsError: true}
	}
	return MCPToolResult{Text: string(res.Body), IsError: res.Status >= 400}
}

// normalizeJSONBody passes JSON through untouched and wraps anything else as a JSON
// string, so the execute wrapper is always valid JSON.
func normalizeJSONBody(b []byte) []byte {
	if json.Valid(b) && len(b) > 0 {
		return b
	}
	q, _ := json.Marshal(string(b))
	return q
}
