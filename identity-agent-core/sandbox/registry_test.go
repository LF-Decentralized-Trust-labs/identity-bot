package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func registryTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	st, err := NewSandboxStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	cv := NewCredentialVault(dir)
	cv.SetKeyProvider(testVaultKeyProvider)
	return &Manager{
		store:       st,
		policy:      NewPolicyEngine(st, NewEventBus()),
		credentials: cv,
		manifests:   map[string]*AppManifest{},
		dataDir:     dir,
	}
}

// testVaultKeyProvider supplies a fixed 32-byte vault key for tests.
func testVaultKeyProvider() ([]byte, error) {
	return []byte("0123456789abcdef0123456789abcdef"), nil
}

func TestExpandPathTemplate(t *testing.T) {
	args := map[string]any{"zone_id": "abc123", "record_id": "r/9", "extra": "kept"}
	path, err := expandPathTemplate("/zones/{zone_id}/dns_records/{record_id}", args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/zones/abc123/dns_records/r%2F9" {
		t.Fatalf("unexpected path: %s", path)
	}
	if _, used := args["zone_id"]; used {
		t.Fatal("used path args must be consumed")
	}
	if _, kept := args["extra"]; !kept {
		t.Fatal("unused args must remain for query/body")
	}
	if _, err := expandPathTemplate("/zones/{zone_id}", map[string]any{}); err == nil {
		t.Fatal("missing path arg must be an error")
	}
}

// A registry-native external_api capability invokes end-to-end through the governed
// path — and writes a signed-shape audit event with a blake3 args hash.
func TestRegistryNativeInvokeGovernedAndAudited(t *testing.T) {
	var gotPath, gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		w.Write([]byte(`{"success":true}`))
	}))
	defer ts.Close()

	m := registryTestManager(t)
	if err := m.credentials.SetCredential("testsvc", []string{"127.0.0.1"}, map[string]string{"Authorization": "Bearer secret-token"}); err != nil {
		t.Fatalf("credential: %v", err)
	}
	rec := CapabilityRecord{
		ID: "testsvc.dns.list", Name: "List", Domain: "dev",
		ExecutorType: "external_api", Impact: "read",
		Egress:   &EgressSpec{BaseURL: ts.URL, Method: "GET", PathTemplate: "/zones/{zone_id}/dns_records", CredentialService: "testsvc"},
		Provider: "registry-native", Enabled: true,
	}
	if err := m.store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	caller := CallerContext{Remote: false, CallerAID: "local-owner", CorrelationID: "corr-1", Transport: "mcp"}
	res, err := m.InvokeCapability(context.Background(), caller, "testsvc.dns.list", []byte(`{"zone_id":"z1"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if res.Status != 200 || gotPath != "/zones/z1/dns_records" {
		t.Fatalf("unexpected result: status=%d path=%s", res.Status, gotPath)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("credential was not injected at egress (got %q)", gotAuth)
	}

	events, err := m.store.QueryInvocationEvents(InvocationEventFilter{CapabilityID: "testsvc.dns.list"})
	if err != nil || len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d (err %v)", len(events), err)
	}
	ev := events[0]
	if ev.ResultStatus != "ok" || ev.CallerAID != "local-owner" || ev.CorrelationID != "corr-1" {
		t.Fatalf("bad audit event: %+v", ev)
	}
	if !strings.HasPrefix(ev.ArgsHash, "blake3:") {
		t.Fatalf("args hash missing: %q", ev.ArgsHash)
	}
}

// A remote caller without scope is default-denied on a registry capability too — and
// the denial itself is audited.
func TestRegistryNativeRemoteDeniedAndAudited(t *testing.T) {
	m := registryTestManager(t)
	rec := CapabilityRecord{
		ID: "testsvc.dns.create", Name: "Create", ExecutorType: "external_api", Impact: "mutating",
		Egress:   &EgressSpec{BaseURL: "http://127.0.0.1:1", Method: "POST", PathTemplate: "/x"},
		Provider: "registry-native", Enabled: true,
	}
	if err := m.store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	caller := CallerContext{Remote: true, CallerAID: "token:ci", CorrelationID: "corr-2"}
	_, err := m.InvokeCapability(context.Background(), caller, "testsvc.dns.create", []byte(`{}`))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
	events, _ := m.store.QueryInvocationEvents(InvocationEventFilter{CapabilityID: "testsvc.dns.create"})
	if len(events) != 1 || events[0].ResultStatus != "denied" {
		t.Fatalf("denial must be audited, got %+v", events)
	}
	// With scope granted, the gateway admits the remote caller (executor then fails on
	// the unreachable egress — governance, not connectivity, is under test here).
	caller.Scopes = []string{"testsvc.dns.create"}
	_, err = m.InvokeCapability(context.Background(), caller, "testsvc.dns.create", []byte(`{}`))
	if errors.Is(err, ErrDenied) {
		t.Fatalf("scoped remote caller must pass ingress, got %v", err)
	}
}

// The embedded Cloudflare reference pack loads, its records are enabled with SAIDs,
// and they surface through tools/list — including the execute meta-tool.
func TestEmbeddedPackAndMCPProjection(t *testing.T) {
	m := registryTestManager(t)
	m.loadCapabilityPacks()
	recs, err := m.store.ListCapabilityRecords()
	if err != nil || len(recs) != 5 {
		t.Fatalf("expected 5 records from the reference pack, got %d (err %v)", len(recs), err)
	}
	for _, r := range recs {
		if r.SAID == "" || !strings.HasPrefix(r.SAID, "blake3:") {
			t.Fatalf("record %s missing SAID", r.ID)
		}
		if r.Egress == nil || r.Egress.CredentialService != "cloudflare" {
			t.Fatalf("record %s missing cloudflare egress", r.ID)
		}
	}
	tools := m.MCPToolsList()
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"infra.zone.list", "infra.dns_record.create", ExecuteToolName} {
		if !names[want] {
			t.Fatalf("tools/list missing %s (have %v)", want, names)
		}
	}
}

// execute routes to the named capability with the inner args.
func TestExecuteMetaTool(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	m := registryTestManager(t)
	rec := CapabilityRecord{
		ID: "svc.thing.get", Name: "Get", ExecutorType: "external_api", Impact: "read",
		Egress:   &EgressSpec{BaseURL: ts.URL, Method: "GET", PathTemplate: "/thing/{id}"},
		Provider: "registry-native", Enabled: true,
	}
	if err := m.store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	caller := CallerContext{Remote: false, CallerAID: "local-owner", CorrelationID: "corr-3"}
	out := m.MCPToolsCall(context.Background(), caller, ExecuteToolName, []byte(`{"capability_id":"svc.thing.get","args":{"id":"42"}}`))
	if out.IsError {
		t.Fatalf("execute failed: %s", out.Text)
	}
	var wrapped struct {
		CapabilityID  string          `json:"capability_id"`
		Status        int             `json:"status"`
		CorrelationID string          `json:"correlation_id"`
		Body          json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal([]byte(out.Text), &wrapped); err != nil {
		t.Fatalf("execute result not JSON: %v", err)
	}
	if wrapped.CapabilityID != "svc.thing.get" || wrapped.Status != 200 || wrapped.CorrelationID != "corr-3" {
		t.Fatalf("unexpected wrapped result: %+v", wrapped)
	}
	out = m.MCPToolsCall(context.Background(), caller, ExecuteToolName, []byte(`{}`))
	if !out.IsError {
		t.Fatal("execute without capability_id must error")
	}
}
