package sandbox

import "context"

// MCPTool is the tool projection of a provided capability for an MCP tools/list.
// (The JSON-RPC framing lives in the server layer; this is just the data.)
type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// MCPToolsList projects the installed plug-in capabilities (discovery) as MCP tools —
// the tools/list side of the agent's single MCP server.
func (m *Manager) MCPToolsList() []MCPTool {
	caps := m.ProvidedCapabilities()
	tools := make([]MCPTool, 0, len(caps))
	for _, c := range caps {
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
	return tools
}

// MCPToolResult is the result of an MCP tools/call.
type MCPToolResult struct {
	Text    string
	IsError bool
}

// MCPToolsCall routes an MCP tools/call through the governed invoke path (ingress ->
// plug-in -> egress). A governance denial or capability error becomes an error
// tool-result (IsError=true) rather than a transport failure — the MCP client sees it
// as the tool's output, which is the protocol-correct shape for an execution error.
func (m *Manager) MCPToolsCall(ctx context.Context, caller CallerContext, name string, args []byte) MCPToolResult {
	res, err := m.InvokeCapability(ctx, caller, name, args)
	if err != nil {
		return MCPToolResult{Text: err.Error(), IsError: true}
	}
	return MCPToolResult{Text: string(res.Body), IsError: res.Status >= 400}
}
