package sandbox

import (
	"strings"
	"testing"
)

func TestAnExternalCallerWithoutATokenIsRefused(t *testing.T) {
	// Without a token a route can only be matched by source address, which never
	// yields a credential. Accepting it would look like it worked and quietly do
	// nothing — the caller would then debug a remote that will not authorise it.
	m := &Manager{proxy: &ProxyManager{routes: map[string]*ProxyRoute{}}}
	err := m.RegisterEgressCaller(ProxyRoute{InstanceID: "w1", CallerAID: "EAgent"})
	if err == nil {
		t.Fatal("a caller with no token must be refused, not silently registered")
	}
	if !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("the error should say why it would not have worked: %v", err)
	}
}

func TestAnExternalCallerNeedsAnID(t *testing.T) {
	m := &Manager{proxy: &ProxyManager{routes: map[string]*ProxyRoute{}}}
	if err := m.RegisterEgressCaller(ProxyRoute{ProxyToken: "tok"}); err == nil {
		t.Fatal("a caller with no id must be refused")
	}
}

func TestRegisteringWithNoProxyIsAnErrorNotAPanic(t *testing.T) {
	m := &Manager{}
	if err := m.RegisterEgressCaller(ProxyRoute{InstanceID: "w1", ProxyToken: "tok"}); err == nil {
		t.Fatal("registering with no proxy running should be an error")
	}
	if _, err := m.ProxyCACertPEM(); err == nil {
		t.Fatal("asking for the CA with no proxy running should be an error")
	}
	if m.ProxyAddr() != "" {
		t.Fatal("no proxy means no address")
	}
}

func TestUnregisteringSomethingUnknownIsSafe(t *testing.T) {
	// Access is revoked far more often in cleanup paths than in happy ones. A
	// revocation that errors because it was already done is one people skip.
	m := &Manager{proxy: &ProxyManager{routes: map[string]*ProxyRoute{}}}
	m.UnregisterEgressCaller("never-registered")
	(&Manager{}).UnregisterEgressCaller("no-proxy-at-all")
}

func TestARegisteredCallerIsIdentifiedAndScoped(t *testing.T) {
	m := &Manager{proxy: &ProxyManager{routes: map[string]*ProxyRoute{}}}
	if err := m.RegisterEgressCaller(ProxyRoute{
		InstanceID: "w1", ProxyToken: "tok-1",
		CallerAID: "EAgentDelegatedAID", GrantSAID: "EGrant",
		CredentialServices: []string{"github"},
	}); err != nil {
		t.Fatal(err)
	}
	got := m.proxy.GetRoute("w1")
	if got == nil || got.CallerAID != "EAgentDelegatedAID" || got.GrantSAID != "EGrant" {
		t.Fatalf("the route must carry the delegated identity, got %+v", got)
	}
	if len(got.CredentialServices) != 1 || got.CredentialServices[0] != "github" {
		t.Fatalf("the route must carry exactly what was granted, got %+v", got.CredentialServices)
	}
	m.UnregisterEgressCaller("w1")
	if m.proxy.GetRoute("w1") != nil {
		t.Fatal("unregistering must remove the route")
	}
}
