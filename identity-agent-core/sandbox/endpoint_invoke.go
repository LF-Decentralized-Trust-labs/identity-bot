package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Sentinel errors so the HTTP layer can map governance outcomes to status codes.
var (
	// ErrCapabilityNotFound: no installed plug-in offers the requested capability.
	ErrCapabilityNotFound = errors.New("capability not found")
	// ErrDenied: the gateway denied the request on ingress (default-deny).
	ErrDenied = errors.New("denied")
)

// CallerContext is who is invoking a capability, as far as governance needs. Remote
// marks a request that arrived over the network (not the local owner); Scopes are the
// capability ids the caller has been granted. Full caller identity + ACDC-scope
// resolution is wired through the governance gateway + delegated identity; this is the
// minimal governance input the endpoint enforces today.
type CallerContext struct {
	Remote bool
	Scopes []string
}

// InvokeResult is a capability's response, routed back through the endpoint.
type InvokeResult struct {
	CapabilityID string `json:"capability_id"`
	Status       int    `json:"status"`
	Body         []byte `json:"-"`
}

// CapabilityInvoker routes a governed request to the running plug-in that provides a
// capability. Split out so the governance pipeline is testable without a live plug-in.
type CapabilityInvoker interface {
	Invoke(ctx context.Context, appID, capabilityID string, body []byte) (*InvokeResult, error)
}

// InvokeCapability is the governed invoke path. The gateway governs BOTH directions;
// neither may be skipped:
//
//	resolve provider -> INGRESS authorize -> route to the plug-in -> EGRESS re-check -> return.
func (m *Manager) InvokeCapability(ctx context.Context, caller CallerContext, capabilityID string, body []byte) (*InvokeResult, error) {
	provider, capDef, ok := m.findProvider(capabilityID)
	if !ok {
		return nil, ErrCapabilityNotFound
	}
	if err := m.authorizeIngress(caller, capDef); err != nil {
		return nil, err
	}
	inv := m.invoker
	if inv == nil {
		inv = &httpInvoker{mgr: m}
	}
	res, err := inv.Invoke(ctx, provider.ID, capabilityID, body)
	if err != nil {
		return nil, err
	}
	return m.checkEgress(caller, capDef, res), nil
}

// findProvider resolves which installed plug-in offers a capability.
func (m *Manager) findProvider(capabilityID string) (*AppManifest, ProvidedCapability, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, manifest := range m.manifests {
		for _, p := range manifest.Provides {
			if p.ID == capabilityID {
				return manifest, p, true
			}
		}
	}
	return nil, ProvidedCapability{}, false
}

// authorizeIngress is the ingress half of the gateway: default-deny, with two
// structural rules enforced here today. Full per-asker ACDC-scope authorization is
// enforced by the governance gateway; wire it in here.
func (m *Manager) authorizeIngress(caller CallerContext, capDef ProvidedCapability) error {
	// A host-control capability (drives the host UI) is never invocable by a remote
	// caller — "don't let the internet drive my desktop".
	if capDef.HostControl && caller.Remote {
		return fmt.Errorf("%w: host_control capability %q is not invocable by a remote caller", ErrDenied, capDef.ID)
	}
	// Remote callers must carry the capability in their granted scope (default-deny).
	// The local owner is allowed. This is the structural default-deny until the gateway
	// + delegated-identity scope check is wired.
	if caller.Remote && !containsStr(caller.Scopes, capDef.ID) {
		return fmt.Errorf("%w: caller lacks scope for capability %q", ErrDenied, capDef.ID)
	}
	return nil
}

// checkEgress is the egress half of the gateway: re-assess a result before it leaves.
// Pass-through + audit hook today; disclosure/filtering rules are wired through the
// governance gateway. The point is the order — results ALWAYS return via egress.
func (m *Manager) checkEgress(caller CallerContext, capDef ProvidedCapability, res *InvokeResult) *InvokeResult {
	// TODO(gateway): apply egress disclosure/filter rules + audit here.
	return res
}

// httpInvoker routes to the running plug-in's local capability API (the plug-in SDK's
// POST /v1/capability/{id} on the instance's display port).
type httpInvoker struct{ mgr *Manager }

func (h *httpInvoker) Invoke(ctx context.Context, appID, capabilityID string, body []byte) (*InvokeResult, error) {
	inst, err := h.mgr.GetRunningInstance(appID)
	if err != nil {
		return nil, fmt.Errorf("plug-in %q is not running: %w", appID, err)
	}
	if inst.DisplayPort == nil {
		return nil, fmt.Errorf("plug-in %q has no reachable capability port", appID)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/v1/capability/%s", *inst.DisplayPort, capabilityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return &InvokeResult{CapabilityID: capabilityID, Status: resp.StatusCode, Body: rb}, nil
}

func containsStr(ss []string, t string) bool {
	for _, s := range ss {
		if s == t {
			return true
		}
	}
	return false
}

// IsLoopbackHost reports whether a request host is local (owner) vs remote.
func IsLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}
