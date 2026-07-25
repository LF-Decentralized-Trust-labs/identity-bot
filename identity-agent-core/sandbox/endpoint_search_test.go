package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func searchTestManager(t *testing.T) *Manager {
	t.Helper()
	m := registryTestManager(t)
	recs := []CapabilityRecord{
		{ID: "cloudflare.dns.list", Name: "List DNS records", Description: "List DNS records in a zone", Domain: "infrastructure", ExecutorType: "external_api", Impact: "read", Provider: "registry-native", Enabled: true,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"zone_id":{"type":"string"}},"required":["zone_id"]}`),
			Egress:      &EgressSpec{BaseURL: "https://api.example.com", Method: "GET", PathTemplate: "/zones/{zone_id}/dns_records", CredentialService: "cloudflare"}},
		{ID: "cloudflare.dns.create", Name: "Create DNS record", Description: "Create a DNS record", Domain: "infrastructure", ExecutorType: "external_api", Impact: "mutating", Provider: "registry-native", Enabled: true},
		{ID: "media.image.create", Name: "Create image", Description: "Generate an image from a prompt", Domain: "media", ExecutorType: "external_api", Impact: "mutating", Provider: "registry-native", Enabled: true},
		{ID: "host.shutdown", Name: "Shut down host", Description: "Power off the machine", Domain: "host", ExecutorType: "host_control", Impact: "mutating", Provider: "registry-native", Enabled: true},
	}
	for _, r := range recs {
		if err := m.store.UpsertCapabilityRecord(r); err != nil {
			t.Fatalf("upsert %s: %v", r.ID, err)
		}
	}
	m.manifests["plug1"] = &AppManifest{
		ID: "plug1",
		Provides: []ProvidedCapability{{
			ID: "plug1.notes.search", Name: "Search notes", Description: "Full-text search over notes",
			RequestContract: "POST {query}", Docs: "Send {query}; returns matches.",
		}},
	}
	return m
}

var localCaller = CallerContext{Remote: false, CallerAID: "local-owner", Transport: "mcp"}

// Ranked deterministic search: exact id first, then prefix, then substring; summaries
// carry no schemas.
func TestSearchRankingAndFilters(t *testing.T) {
	m := searchTestManager(t)

	got := m.SearchCapabilities(context.Background(), localCaller, SearchQuery{Query: "dns"})
	if len(got) != 2 {
		t.Fatalf("dns query: expected 2 results, got %d (%+v)", len(got), got)
	}
	got = m.SearchCapabilities(context.Background(), localCaller, SearchQuery{Query: "cloudflare.dns.list"})
	if len(got) == 0 || got[0].CapabilityID != "cloudflare.dns.list" {
		t.Fatalf("exact id must rank first, got %+v", got)
	}

	got = m.SearchCapabilities(context.Background(), localCaller, SearchQuery{Domain: "media"})
	if len(got) != 1 || got[0].CapabilityID != "media.image.create" {
		t.Fatalf("domain filter: %+v", got)
	}
	got = m.SearchCapabilities(context.Background(), localCaller, SearchQuery{ExecutorType: "plugin"})
	if len(got) != 1 || got[0].CapabilityID != "plug1.notes.search" {
		t.Fatalf("executor filter: %+v", got)
	}

	all := m.SearchCapabilities(context.Background(), localCaller, SearchQuery{})
	if len(all) != 5 {
		t.Fatalf("empty query must browse the catalog, got %d", len(all))
	}
	limited := m.SearchCapabilities(context.Background(), localCaller, SearchQuery{Limit: 2})
	if len(limited) != 2 {
		t.Fatalf("limit ignored, got %d", len(limited))
	}
	// description-only match still surfaces, ranked below name matches
	got = m.SearchCapabilities(context.Background(), localCaller, SearchQuery{Query: "prompt"})
	if len(got) != 1 || got[0].CapabilityID != "media.image.create" {
		t.Fatalf("description match: %+v", got)
	}
}

// Search never reveals what the caller could not invoke: a remote caller sees only
// its granted scopes, and host_control never surfaces remotely.
func TestSearchFiltersToEntitlements(t *testing.T) {
	m := searchTestManager(t)
	remote := CallerContext{Remote: true, CallerAID: "token:ci", Scopes: []string{"cloudflare.dns.list"}}

	got := m.SearchCapabilities(context.Background(), remote, SearchQuery{})
	if len(got) != 1 || got[0].CapabilityID != "cloudflare.dns.list" {
		t.Fatalf("remote caller must see only granted scopes, got %+v", got)
	}

	remote.Scopes = append(remote.Scopes, "host.shutdown")
	got = m.SearchCapabilities(context.Background(), remote, SearchQuery{Query: "host.shutdown"})
	if len(got) != 0 {
		t.Fatalf("host_control must never surface to a remote caller, got %+v", got)
	}
}

// Describe serves the full record — and is gated exactly like execute, with
// not-found and not-entitled indistinguishable.
func TestDescribeCapability(t *testing.T) {
	m := searchTestManager(t)

	d, err := m.DescribeCapability(context.Background(), localCaller, "cloudflare.dns.list")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if d.CapabilityID != "cloudflare.dns.list" || d.ExecutorType != "external_api" || d.Impact != "read" {
		t.Fatalf("bad detail: %+v", d)
	}
	var schema map[string]any
	if err := json.Unmarshal(d.InputSchema, &schema); err != nil || schema["required"] == nil {
		t.Fatalf("describe must carry the full input schema: %v (%s)", err, d.InputSchema)
	}
	if d.Invocation == "" {
		t.Fatal("describe must include the execute invocation hint")
	}

	pd, err := m.DescribeCapability(context.Background(), localCaller, "plug1.notes.search")
	if err != nil {
		t.Fatalf("plugin describe: %v", err)
	}
	if pd.ExecutorType != "plugin" || pd.Provider != "plug1" || pd.RequestContract == "" {
		t.Fatalf("bad plugin detail: %+v", pd)
	}

	if _, err := m.DescribeCapability(context.Background(), localCaller, "nope.missing"); !errors.Is(err, ErrCapabilityNotFound) {
		t.Fatalf("missing capability: %v", err)
	}
	remote := CallerContext{Remote: true, CallerAID: "token:ci"}
	if _, err := m.DescribeCapability(context.Background(), remote, "cloudflare.dns.list"); !errors.Is(err, ErrCapabilityNotFound) {
		t.Fatalf("unentitled describe must read as not found, got %v", err)
	}
}

// The MCP surface exposes all three meta-tools and routes search/describe calls.
func TestMCPSearchDescribeTools(t *testing.T) {
	m := searchTestManager(t)

	names := map[string]bool{}
	for _, tl := range m.MCPToolsList(localCaller) {
		names[tl.Name] = true
	}
	for _, want := range []string{ExecuteToolName, SearchToolName, DescribeToolName} {
		if !names[want] {
			t.Fatalf("tools/list missing %s", want)
		}
	}

	out := m.MCPToolsCall(context.Background(), localCaller, SearchToolName, []byte(`{"query":"dns"}`))
	if out.IsError {
		t.Fatalf("search call failed: %s", out.Text)
	}
	var sr struct {
		Capabilities []CapabilitySummary `json:"capabilities"`
		Count        int                 `json:"count"`
	}
	if err := json.Unmarshal([]byte(out.Text), &sr); err != nil || sr.Count != 2 {
		t.Fatalf("bad search result: %v %s", err, out.Text)
	}

	out = m.MCPToolsCall(context.Background(), localCaller, DescribeToolName, []byte(`{"capability_id":"cloudflare.dns.list"}`))
	if out.IsError {
		t.Fatalf("describe call failed: %s", out.Text)
	}
	var detail CapabilityDetail
	if err := json.Unmarshal([]byte(out.Text), &detail); err != nil || detail.CapabilityID != "cloudflare.dns.list" {
		t.Fatalf("bad describe result: %v %s", err, out.Text)
	}
	out = m.MCPToolsCall(context.Background(), localCaller, DescribeToolName, []byte(`{}`))
	if !out.IsError {
		t.Fatal("describe without capability_id must error")
	}
}

// execute's wrapped result cites the signed audit event it wrote.
func TestExecuteReturnsAuditEventID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	m := registryTestManager(t)
	rec := CapabilityRecord{
		ID: "svc.thing.get", Name: "Get", ExecutorType: "external_api", Impact: "read",
		Egress:   &EgressSpec{BaseURL: ts.URL, Method: "GET", PathTemplate: "/thing"},
		Provider: "registry-native", Enabled: true,
	}
	if err := m.store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	out := m.MCPToolsCall(context.Background(), localCaller, ExecuteToolName, []byte(`{"capability_id":"svc.thing.get"}`))
	if out.IsError {
		t.Fatalf("execute failed: %s", out.Text)
	}
	var wrapped struct {
		AuditEventID int64 `json:"audit_event_id"`
	}
	if err := json.Unmarshal([]byte(out.Text), &wrapped); err != nil || wrapped.AuditEventID == 0 {
		t.Fatalf("execute must return the audit event id, got %s", out.Text)
	}
	events, err := m.store.QueryInvocationEvents(InvocationEventFilter{CapabilityID: "svc.thing.get"})
	if err != nil || len(events) != 1 || events[0].ID != wrapped.AuditEventID {
		t.Fatalf("audit_event_id must reference the written event: %v %+v", err, events)
	}
}
