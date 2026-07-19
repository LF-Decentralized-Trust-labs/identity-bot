package sandbox

import (
	"context"
	"errors"
	"testing"
)

// denyAllAuthorizer is a stand-in for an injected governance gateway: it denies every
// ingress and tags every egress, proving the seam is honored (drop-in for the gateway).
type denyAllAuthorizer struct{ egressTagged bool }

func (a *denyAllAuthorizer) AuthorizeIngress(ctx context.Context, caller CallerContext, capDef ProvidedCapability) error {
	return errors.New("policy: denied by injected gateway")
}
func (a *denyAllAuthorizer) FilterEgress(ctx context.Context, caller CallerContext, capDef ProvidedCapability, res *InvokeResult) *InvokeResult {
	a.egressTagged = true
	return res
}

// An injected Authorizer overrides the structural default on ingress.
func TestInjectedAuthorizerOverridesIngress(t *testing.T) {
	f := &fakeInvoker{}
	m := invokeTestManager(f)
	m.authorizer = &denyAllAuthorizer{}

	// Local owner would pass the structural default, but the injected gateway denies.
	_, err := m.InvokeCapability(context.Background(), CallerContext{Remote: false}, "headless-browser", nil)
	if err == nil {
		t.Fatal("injected authorizer should have denied the request")
	}
	if f.called {
		t.Fatal("denied request must not be routed")
	}
}

// The injected Authorizer's egress filter runs on an allowed call.
func TestInjectedAuthorizerEgressRuns(t *testing.T) {
	allowEgress := &recordingAuthorizer{}
	f := &fakeInvoker{result: &InvokeResult{Status: 200, Body: []byte("ok")}}
	m := invokeTestManager(f)
	m.authorizer = allowEgress

	_, err := m.InvokeCapability(context.Background(), CallerContext{Remote: false}, "headless-browser", nil)
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if !allowEgress.egressRan || !f.called {
		t.Fatalf("expected route + egress filter to run (routed=%v egress=%v)", f.called, allowEgress.egressRan)
	}
}

type recordingAuthorizer struct{ egressRan bool }

func (recordingAuthorizer) AuthorizeIngress(ctx context.Context, caller CallerContext, capDef ProvidedCapability) error {
	return nil // allow
}
func (a *recordingAuthorizer) FilterEgress(ctx context.Context, caller CallerContext, capDef ProvidedCapability, res *InvokeResult) *InvokeResult {
	a.egressRan = true
	return res
}

// With no injected Authorizer, the structural default still applies (regression guard).
func TestDefaultAuthorizerStillStructural(t *testing.T) {
	f := &fakeInvoker{}
	m := invokeTestManager(f) // no m.authorizer set
	_, err := m.InvokeCapability(context.Background(), CallerContext{Remote: true}, "native-computer-use", nil)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("default structural authorizer should deny remote host_control, got %v", err)
	}
}
