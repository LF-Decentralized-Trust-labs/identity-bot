package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/appcall"
)

// manifestJSON is the least an app's manifest needs to load, providing caps.
func manifestJSON(id string, caps ...string) []byte {
	provides := []map[string]string{}
	for _, c := range caps {
		provides = append(provides, map[string]string{"id": c})
	}
	b, _ := json.Marshal(map[string]any{
		"id": id, "name": id, "execution_type": "compiled", "binary": map[string]string{"path": "/bin/true"},
		"display_method": "webview", "network_mode": "local_only", "network": map[string]string{"tls_mode": "mitm"},
		"log_level": "none", "resources": map[string]int{"memory_mb": 64}, "provides": provides,
	})
	return b
}

func managerWith(t *testing.T, manifests map[string][]byte) *Manager {
	t.Helper()
	dir := t.TempDir()
	for name, b := range manifests {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := NewManager(ManagerConfig{DataDir: t.TempDir(), ManifestsDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	if err := m.LoadManifests(); err != nil {
		t.Fatal(err)
	}
	return m
}

// Two apps declaring one capability are both refused, so neither receives the
// other's callers. Before, whichever the map iterated to first got the call.
func TestTwoAppsCannotProvideOneCapability(t *testing.T) {
	m := managerWith(t, map[string][]byte{
		"tracker":   manifestJSON("tracker", "tracker.lease", "tracker.read"),
		"impostor":  manifestJSON("impostor", "tracker.lease"),
		"bystander": manifestJSON("bystander", "notes.read"),
	})
	if _, _, ok := m.findProvider("tracker.lease"); ok {
		t.Fatal("a capability two apps declare was given a provider")
	}
	if _, _, ok := m.findProvider("tracker.read"); ok {
		t.Fatal("an app in a collision was loaded anyway")
	}
	if p, _, ok := m.findProvider("notes.read"); !ok || p.ID != "bystander" {
		t.Fatal("an app with nothing in common with the collision was refused")
	}
}

// Even with two providers in place, the invoke path refuses rather than chooses.
func TestAnInvocationWithTwoProvidersIsRefusedNotRouted(t *testing.T) {
	f := &fakeInvoker{result: &InvokeResult{Status: 200}}
	m := &Manager{invoker: f, manifests: map[string]*AppManifest{
		"tracker":  {ID: "tracker", Provides: []ProvidedCapability{{ID: "tracker.lease"}}},
		"impostor": {ID: "impostor", Provides: []ProvidedCapability{{ID: "tracker.lease"}}},
	}}
	_, err := m.InvokeCapability(context.Background(), CallerContext{Remote: false}, "tracker.lease", nil)
	if !errors.Is(err, ErrDenied) || f.called {
		t.Fatalf("an ambiguous capability was routed (called=%v): %v", f.called, err)
	}
}

// An app cannot shadow a capability this Identity Agent's registry provides.
func TestAnAppCannotShadowARegistryCapability(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shadow.json"), manifestJSON("shadow", "registry.thing"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(ManagerConfig{DataDir: t.TempDir(), ManifestsDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	if err := m.store.UpsertCapabilityRecord(CapabilityRecord{ID: "registry.thing", Name: "thing",
		ExecutorType: "external_api", Enabled: true, Egress: &EgressSpec{BaseURL: "https://example.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadManifests(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.manifests["shadow"]; ok {
		t.Fatal("an app declaring a registry capability's id was loaded")
	}
}

// runningApp is a capability server that checks the Identity Agent's stamp,
// recorded as the running instance of appID.
func runningApp(t *testing.T, m *Manager, appID string, seen *appcall.Caller) {
	t.Helper()
	key, err := m.AppCallKey(appID)
	if err != nil {
		t.Fatal(err)
	}
	v, err := appcall.NewVerifier(key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(v.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen, _ = appcall.FromContext(r.Context())
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, `{"echo":%s}`, b)
	})))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	port := ln.Addr().(*net.TCPAddr).Port
	if err := m.store.SaveInstance(Instance{ID: appID + "-1", AppID: appID, Status: "running",
		DisplayPort: &port, TLSMode: "mitm", LogLevel: "none"}); err != nil {
		t.Fatal(err)
	}
}

// The app is told who the Identity Agent admitted, under its own key.
func TestAnAppIsToldWhoCalled(t *testing.T) {
	m := managerWith(t, map[string][]byte{"tracker": manifestJSON("tracker", "tracker.lease")})
	var seen appcall.Caller
	runningApp(t, m, "tracker", &seen)

	caller := CallerContext{Remote: true, Scopes: []string{"tracker.lease"}, CallerAID: "EAgent",
		DelegationChain: []string{"EAgent", "EOrg"}, AuthLevel: "body_signed", BodyHost: "BBody",
		GrantSAID: "EGrant", Session: "run-7"}
	res, err := m.InvokeCapability(context.Background(), caller, "tracker.lease", []byte(`{"task":"T-1"}`))
	if err != nil || res.Status != 200 {
		t.Fatalf("the call did not reach the app: %v %+v", err, res)
	}
	want := appcall.Caller{Kind: appcall.KindAIAgent, Agent: "EAgent", Machine: "BBody",
		AuthLevel: "body_signed", Grant: "EGrant", Session: "run-7"}
	if seen != want {
		t.Fatalf("the app was told %+v, not %+v", seen, want)
	}
}

// The same app refuses a call that did not come stamped from the Identity
// Agent, which is the path problem #379 described: straight to its port.
func TestAnAppRefusesACallTheIdentityAgentDidNotStamp(t *testing.T) {
	m := managerWith(t, map[string][]byte{"tracker": manifestJSON("tracker", "tracker.lease")})
	var seen appcall.Caller
	runningApp(t, m, "tracker", &seen)
	url, err := m.GetDisplayURL("tracker")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", url+"/v1/capability/tracker.lease", nil)
	req.Header.Set(appcall.HeaderKind, appcall.KindOwner)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || seen != (appcall.Caller{}) {
		t.Fatalf("an unstamped call reached the app: %d %+v", res.StatusCode, seen)
	}
}

// An app's key is kept, so a restart of the Identity Agent does not strand an
// app still running with the old one; and two apps never share one.
func TestAnAppsCallKeyIsItsOwnAndKept(t *testing.T) {
	m := &Manager{dataDir: t.TempDir()}
	a1, err := m.AppCallKey("tracker")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := m.AppCallKey("tracker")
	b, _ := m.AppCallKey("notes")
	if string(a1) != string(a2) {
		t.Fatal("an app's key changed between two asks")
	}
	if string(a1) == string(b) {
		t.Fatal("two apps were given the same key")
	}
	if _, err := m.AppCallKey("../escape"); err == nil {
		t.Fatal("an app id naming another directory was given a key")
	}
	fi, err := os.Stat(filepath.Join(m.dataDir, appCallKeysDir, "tracker.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("the key file is readable by others: %v", fi.Mode().Perm())
	}
}

// The owner is told as the owner, with the owner's identifier when the gate
// knew it, and a host plug-in machine is not mistaken for an AI agent.
func TestTheCallerAnAppIsToldByKind(t *testing.T) {
	for _, c := range []struct {
		in   CallerContext
		want appcall.Caller
	}{
		{CallerContext{CallerAID: "local-owner"}, appcall.Caller{Kind: appcall.KindOwner, AuthLevel: "local"}},
		{CallerContext{Remote: true, Owner: true, CallerAID: "EOwner", AuthLevel: "owner_signed"},
			appcall.Caller{Kind: appcall.KindOwner, Agent: "EOwner", AuthLevel: "owner_signed"}},
		{CallerContext{CallerAID: "token:ci"}, appcall.Caller{Kind: appcall.KindToken, Agent: "ci"}},
		{CallerContext{CallerAID: "EMachine", DelegationChain: []string{"EMachine"}, AuthLevel: "signed_headers"},
			appcall.Caller{Kind: appcall.KindMachine, Agent: "EMachine", AuthLevel: "signed_headers"}},
	} {
		if got := theCallerAnAppIsTold(c.in); got != c.want {
			t.Errorf("%+v was told as %+v, not %+v", c.in, got, c.want)
		}
	}
}
