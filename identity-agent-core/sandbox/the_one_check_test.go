package sandbox

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/permission"
)

// A capability's minimum is honoured where the gateway authorises an
// invocation: one set to 90 is refused at the placeholder 80, and the refusal
// is audited. Before the one check existed the gateway had no identity
// requirement at all, and this call ran.
func TestACapabilityNeedingNinetyIsRefusedAtTheGateway(t *testing.T) {
	ran := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	m := registryTestManager(t)
	rec := CapabilityRecord{
		ID: "testsvc.high", Name: "High", ExecutorType: "external_api", Impact: "mutating",
		Egress:   &EgressSpec{BaseURL: ts.URL, Method: "POST", PathTemplate: "/x"},
		Provider: "registry-native", Enabled: true,
		MinimumScore: 90,
	}
	if err := m.store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got, _ := m.store.GetCapabilityRecord("testsvc.high"); got == nil || got.MinimumScore != 90 {
		t.Fatalf("the minimum did not survive being stored: %+v", got)
	}

	caller := permission.CallerContext{CallerAID: "local-owner", CorrelationID: "corr-90"}
	_, err := m.InvokeCapability(context.Background(), caller, "testsvc.high", []byte(`{}`))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("a capability needing 90 was not refused at 80: %v", err)
	}
	if ran {
		t.Fatal("the capability ran")
	}
	events, _ := m.store.QueryInvocationEvents(InvocationEventFilter{CapabilityID: "testsvc.high"})
	if len(events) != 1 || events[0].ResultStatus != "denied" {
		t.Fatalf("the refusal was not audited: %+v", events)
	}
}

// A record that sets no minimum keeps the content address it had before the
// field existed, so no capability's SAID moved. The value is pinned from the
// code before minimum_score was added.
func TestNoMinimumLeavesTheContentAddressAlone(t *testing.T) {
	const before = "blake3:06b432e629b78f257a3313631db57da091ef71f82c7a9f9fd1eb320fe843c6e0"
	rec := CapabilityRecord{ID: "demo.pinned", Name: "Pinned", Domain: "demo",
		ExecutorType: "external_api", Impact: "read", Provider: "registry-native", Enabled: true}
	if got := computeCapabilitySAID(rec); got != before {
		t.Fatalf("a record with no minimum changed its content address: %s, was %s", got, before)
	}
	rec.MinimumScore = 90
	if computeCapabilitySAID(rec) == before {
		t.Fatal("a set minimum is not part of what the content address covers")
	}
}
