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
// capability ids the caller has been granted. CallerAID identifies the caller for the
// audit trail (a delegated AID once ACDC resolution lands; a token identity or
// "local-owner" until then). CorrelationID is minted at the origin request and
// propagated through every hop so one action's full path is one query. Full caller
// identity + ACDC-scope resolution is wired through the governance gateway + delegated
// identity; this is the minimal governance input the endpoint enforces today.
type CallerContext struct {
	Remote        bool
	Scopes        []string
	CallerAID     string
	CorrelationID string
	Transport     string
}

// InvokeResult is a capability's response, routed back through the endpoint.
// AuditEventID references the signed invocation-log event this call wrote, so a
// caller can cite the governance record for its own action.
type InvokeResult struct {
	CapabilityID string `json:"capability_id"`
	Status       int    `json:"status"`
	AuditEventID int64  `json:"audit_event_id,omitempty"`
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
//	resolve provider -> INGRESS authorize -> route to the executor -> EGRESS re-check -> return.
//
// A capability resolves either to a running plug-in (manifest-provided) or to a
// registry-native record (e.g. a governed external API); both route through the same
// Authorizer. Every outcome — including a denial — writes one signed audit event.
func (m *Manager) InvokeCapability(ctx context.Context, caller CallerContext, capabilityID string, body []byte) (*InvokeResult, error) {
	start := time.Now()
	executorType := "plugin"
	provider, capDef, ok := m.findProvider(capabilityID)
	var rec *CapabilityRecord
	if !ok {
		rec = m.registryRecord(capabilityID)
		if rec == nil {
			return nil, ErrCapabilityNotFound
		}
		capDef = rec.asProvidedCapability()
		executorType = rec.ExecutorType
	}
	auth := m.authz()
	if err := auth.AuthorizeIngress(ctx, caller, capDef); err != nil {
		m.recordInvocation(caller, capabilityID, executorType, body, "denied", start)
		return nil, err
	}
	// One screen = one driver: host_control invocations serialize per capability
	// so concurrent callers queue instead of interleaving primitives.
	if capDef.HostControl {
		l := hostControlLock(capabilityID)
		l.Lock()
		defer l.Unlock()
	}
	var res *InvokeResult
	var err error
	if rec != nil && rec.ExecutorType == "external_api" {
		res, err = m.invokeExternalAPI(ctx, rec, body)
	} else if rec != nil {
		err = fmt.Errorf("capability %q: executor type %q is not yet invocable", capabilityID, rec.ExecutorType)
	} else {
		inv := m.invoker
		if inv == nil {
			inv = &httpInvoker{mgr: m}
		}
		res, err = inv.Invoke(ctx, provider.ID, capabilityID, body)
	}
	if err != nil {
		m.recordInvocation(caller, capabilityID, executorType, body, "error", start)
		return nil, err
	}
	out := auth.FilterEgress(ctx, caller, capDef, res)
	status := "ok"
	if out != nil && out.Status >= 400 {
		status = "error"
	}
	eventID := m.recordInvocation(caller, capabilityID, executorType, body, status, start)
	if out != nil {
		out.AuditEventID = eventID
	}
	return out, nil
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

// httpInvoker routes to the running plug-in's local capability API (the plug-in SDK's
// POST /v1/capability/{id} on the instance's display port).
type httpInvoker struct{ mgr *Manager }

func (h *httpInvoker) Invoke(ctx context.Context, appID, capabilityID string, body []byte) (*InvokeResult, error) {
	inst, err := h.mgr.GetRunningInstance(appID)
	if err != nil {
		return nil, fmt.Errorf("plug-in %q is not running: %w", appID, err)
	}
	if inst == nil {
		return nil, fmt.Errorf("plug-in %q is not running (install and launch it first)", appID)
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
