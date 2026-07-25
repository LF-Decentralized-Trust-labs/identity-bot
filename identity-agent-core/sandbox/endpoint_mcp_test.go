package sandbox

import (
	"context"
	"testing"
)

func TestMCPToolsList(t *testing.T) {
	m := invokeTestManager(&fakeInvoker{})
	// Local owner (Remote false) sees the flat capabilities + the meta-tools.
	tools := m.MCPToolsList(CallerContext{})
	// Plug-in capabilities plus the trailing execute/search/describe meta-tools.
	if len(tools) != 5 {
		t.Fatalf("expected 5 tools, got %d", len(tools))
	}
	// Sorted by id (ProvidedCapabilities sorts): headless-browser, native-computer-use;
	// the meta-tools are appended last.
	if tools[0].Name != "headless-browser" || tools[1].Name != "native-computer-use" {
		t.Fatalf("tool names/order: %s, %s", tools[0].Name, tools[1].Name)
	}
	if tools[2].Name != ExecuteToolName || tools[3].Name != SearchToolName || tools[4].Name != DescribeToolName {
		t.Fatalf("expected trailing execute/search/describe meta-tools, got %s, %s, %s", tools[2].Name, tools[3].Name, tools[4].Name)
	}
	// host_control capability is flagged in its description (local-owner-only).
	if !contains(tools[1].Description, "host-control") {
		t.Errorf("native-computer-use tool should note host-control: %q", tools[1].Description)
	}
	if tools[0].InputSchema["type"] != "object" {
		t.Errorf("expected object input schema")
	}
}

// A remote caller with no granted scopes must see ONLY the three meta-tools — no
// capability names leak through tools/list, matching search/describe filtering.
func TestMCPToolsListRemoteHidesCapabilities(t *testing.T) {
	m := invokeTestManager(&fakeInvoker{})
	tools := m.MCPToolsList(CallerContext{Remote: true, CallerAID: "token:anon"})
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.Name] = true
	}
	if len(tools) != 3 || !names[ExecuteToolName] || !names[SearchToolName] || !names[DescribeToolName] {
		t.Fatalf("remote caller must see only the 3 meta-tools, got %d: %v", len(tools), names)
	}
	for _, leaked := range []string{"headless-browser", "native-computer-use"} {
		if names[leaked] {
			t.Fatalf("capability %q leaked to an unentitled remote caller", leaked)
		}
	}

	// A remote caller granted one capability sees exactly that one, plus meta-tools.
	scoped := m.MCPToolsList(CallerContext{Remote: true, CallerAID: "token:ci", Scopes: []string{"headless-browser"}})
	sn := map[string]bool{}
	for _, tl := range scoped {
		sn[tl.Name] = true
	}
	if !sn["headless-browser"] || sn["native-computer-use"] || len(scoped) != 4 {
		t.Fatalf("scoped remote caller should see only its granted capability + meta-tools, got %d: %v", len(scoped), sn)
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
