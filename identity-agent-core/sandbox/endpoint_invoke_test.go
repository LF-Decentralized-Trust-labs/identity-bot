package sandbox

import (
	"context"
	"errors"
	"testing"
)

type fakeInvoker struct {
	called bool
	result *InvokeResult
}

func (f *fakeInvoker) Invoke(ctx context.Context, appID, capabilityID string, body []byte) (*InvokeResult, error) {
	f.called = true
	return f.result, nil
}

func invokeTestManager(inv CapabilityInvoker) *Manager {
	return &Manager{
		invoker: inv,
		manifests: map[string]*AppManifest{
			"native-computer-use": {
				ID:       "native-computer-use",
				Provides: []ProvidedCapability{{ID: "native-computer-use", HostControl: true}},
			},
			"headless-browser": {
				ID:       "headless-browser",
				Provides: []ProvidedCapability{{ID: "headless-browser", HostControl: false}},
			},
		},
	}
}

// A host_control capability must be denied for a remote caller, and never routed.
func TestInvokeHostControlRemoteDenied(t *testing.T) {
	f := &fakeInvoker{}
	m := invokeTestManager(f)
	_, err := m.InvokeCapability(context.Background(), CallerContext{Remote: true}, "native-computer-use", nil)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
	if f.called {
		t.Fatal("a denied request must not be routed to the plug-in")
	}
}

// A remote caller without the capability in scope is denied (default-deny), not routed.
func TestInvokeRemoteWithoutScopeDenied(t *testing.T) {
	f := &fakeInvoker{}
	m := invokeTestManager(f)
	_, err := m.InvokeCapability(context.Background(), CallerContext{Remote: true}, "headless-browser", nil)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
	if f.called {
		t.Fatal("default-deny: must not route")
	}
}

// A remote caller WITH the capability in scope is routed and the result returned.
func TestInvokeRemoteWithScopeRoutes(t *testing.T) {
	f := &fakeInvoker{result: &InvokeResult{CapabilityID: "headless-browser", Status: 200, Body: []byte(`{"ok":true}`)}}
	m := invokeTestManager(f)
	res, err := m.InvokeCapability(context.Background(),
		CallerContext{Remote: true, Scopes: []string{"headless-browser"}}, "headless-browser", []byte("{}"))
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if !f.called || res.Status != 200 {
		t.Fatalf("expected routed with 200, called=%v status=%d", f.called, res.Status)
	}
}

// The local owner can invoke even a host_control capability.
func TestInvokeLocalOwnerRoutesHostControl(t *testing.T) {
	f := &fakeInvoker{result: &InvokeResult{Status: 200}}
	m := invokeTestManager(f)
	_, err := m.InvokeCapability(context.Background(), CallerContext{Remote: false}, "native-computer-use", nil)
	if err != nil || !f.called {
		t.Fatalf("local owner should invoke host_control: err=%v called=%v", err, f.called)
	}
}

// Unknown capability -> not found, never routed.
func TestInvokeUnknownCapability(t *testing.T) {
	f := &fakeInvoker{}
	m := invokeTestManager(f)
	_, err := m.InvokeCapability(context.Background(), CallerContext{}, "does-not-exist", nil)
	if !errors.Is(err, ErrCapabilityNotFound) {
		t.Fatalf("expected ErrCapabilityNotFound, got %v", err)
	}
	if f.called {
		t.Fatal("must not route an unknown capability")
	}
}
