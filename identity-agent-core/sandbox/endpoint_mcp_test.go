package sandbox

import (
	"context"
	"testing"
)

func TestMCPToolsList(t *testing.T) {
	m := invokeTestManager(&fakeInvoker{})
	tools := m.MCPToolsList()
	// Plug-in capabilities plus the trailing execute meta-tool.
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}
	// Sorted by id (ProvidedCapabilities sorts): headless-browser, native-computer-use;
	// the execute meta-tool is appended last.
	if tools[0].Name != "headless-browser" || tools[1].Name != "native-computer-use" {
		t.Fatalf("tool names/order: %s, %s", tools[0].Name, tools[1].Name)
	}
	if tools[2].Name != ExecuteToolName {
		t.Fatalf("expected trailing execute meta-tool, got %s", tools[2].Name)
	}
	// host_control capability is flagged in its description (local-owner-only).
	if !contains(tools[1].Description, "host-control") {
		t.Errorf("native-computer-use tool should note host-control: %q", tools[1].Description)
	}
	if tools[0].InputSchema["type"] != "object" {
		t.Errorf("expected object input schema")
	}
}

// tools/call for a host_control capability from a remote caller is denied → IsError,
// and never routed (governance reused from the invoke path).
func TestMCPToolsCallDeniedRemote(t *testing.T) {
	f := &fakeInvoker{}
	m := invokeTestManager(f)
	tr := m.MCPToolsCall(context.Background(), CallerContext{Remote: true}, "native-computer-use", []byte("{}"))
	if !tr.IsError {
		t.Fatalf("remote host_control call should be an error result")
	}
	if f.called {
		t.Fatal("denied call must not route to the plug-in")
	}
}

// tools/call for an in-scope capability routes and returns the plug-in's output.
func TestMCPToolsCallRoutes(t *testing.T) {
	f := &fakeInvoker{result: &InvokeResult{Status: 200, Body: []byte(`{"ok":true}`)}}
	m := invokeTestManager(f)
	tr := m.MCPToolsCall(context.Background(),
		CallerContext{Remote: true, Scopes: []string{"headless-browser"}}, "headless-browser", []byte("{}"))
	if tr.IsError {
		t.Fatalf("expected success, got error: %s", tr.Text)
	}
	if tr.Text != `{"ok":true}` {
		t.Fatalf("expected plug-in body, got %q", tr.Text)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
