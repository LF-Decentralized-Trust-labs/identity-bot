package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"time"

	"identity-agent-core/activitylog"
	"identity-agent-core/appcall"
	"identity-agent-core/permission"
)

// enforceResourceConstraints denies an invocation whose arguments fall outside the
// grant's per-capability resource constraints (permission.CheckResourceConstraints).
func enforceResourceConstraints(constraints map[string]interface{}, capabilityID string, body []byte) error {
	return permission.CheckResourceConstraints(constraints, capabilityID, body)
}

// Sentinel errors so the HTTP layer can map governance outcomes to status codes.
var (
	// ErrCapabilityNotFound: no installed plug-in offers the requested capability.
	ErrCapabilityNotFound = errors.New("capability not found")
	// ErrDenied: the gateway denied the request on ingress (default-deny).
	ErrDenied = errors.New("denied")
)

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
//
// caller is who the Identity Agent admitted, which the invoker passes on to the
// app in a form the app can verify (package appcall).
type CapabilityInvoker interface {
	Invoke(ctx context.Context, caller permission.CallerContext, appID, capabilityID string, body []byte) (*InvokeResult, error)
}

// InvokeCapability is the governed invoke path. The gateway governs BOTH directions;
// neither may be skipped:
//
//	resolve provider -> INGRESS authorize -> route to the executor -> EGRESS re-check -> return.
//
// A capability resolves either to a running plug-in (manifest-provided) or to a
// registry-native record (e.g. a governed external API); both route through the same
// Authorizer. Every outcome — including a denial — writes one signed audit event.
func (m *Manager) InvokeCapability(ctx context.Context, caller permission.CallerContext, capabilityID string, body []byte) (*InvokeResult, error) {
	start := time.Now()
	executorType := "plugin"
	provider, capDef, perr := m.theOneProvider(capabilityID)
	if perr != nil {
		m.log.RecordInvocationDetail(caller, capabilityID, executorType, body, "denied", start,
			activitylog.EventDetail{StatusReason: "provider: " + perr.Error()})
		return nil, fmt.Errorf("%w: %s", ErrDenied, perr.Error())
	}
	ok := provider != nil
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
		m.log.RecordInvocationDetail(caller, capabilityID, executorType, body, "denied", start,
			activitylog.EventDetail{StatusReason: "ingress: " + err.Error()})
		return nil, err
	}
	// The one check, the same function a person at a controller passes: the
	// caller's identity score against this capability's minimum, then whether
	// they may do it at all. An AI agent's score comes from the same
	// placeholder as a person's until human authentication is built, so today
	// this refuses only a capability whose minimum is set above 80.
	if ok, why := passesTheOneCheck(caller, capDef, start); !ok {
		m.log.RecordInvocationDetail(caller, capabilityID, executorType, body, "denied", start,
			activitylog.EventDetail{StatusReason: "the one check: " + why})
		return nil, fmt.Errorf("%w: %s", ErrDenied, why)
	}
	// Per-capability resource constraints from the caller's grant (e.g. a zone
	// allowlist) are enforced against the request arguments here, where the body
	// is available.
	if err := enforceResourceConstraints(caller.ResourceConstraints, capabilityID, body); err != nil {
		m.log.RecordInvocationDetail(caller, capabilityID, executorType, body, "denied", start,
			activitylog.EventDetail{StatusReason: "resource constraint: " + err.Error()})
		return nil, fmt.Errorf("%w: %s", ErrDenied, err.Error())
	}
	// The action is recorded before it runs. If that record cannot be written
	// (no signature, an unreadable previous row, the database refusing), the
	// action does not run: an action the log cannot account for is the one
	// thing the log exists to rule out.
	intentID, err := m.log.RecordIntent(caller, capabilityID, executorType, body, start)
	if err != nil {
		log.Printf("[audit] REFUSED %s for %s: the record could not be written first: %v", capabilityID, caller.CallerAID, err)
		return nil, fmt.Errorf("%w: %v", activitylog.ErrNotRecorded, err)
	}
	// One screen = one driver: host_control invocations serialize per capability
	// so concurrent callers queue instead of interleaving primitives.
	if capDef.HostControl {
		l := hostControlLock(capabilityID)
		l.Lock()
		defer l.Unlock()
	}
	var res *InvokeResult
	if rec != nil && rec.ExecutorType == "external_api" {
		res, err = m.invokeExternalAPI(ctx, rec, body)
	} else if rec != nil {
		if ex := executorFor(rec.ExecutorType); ex != nil {
			res, err = ex.Execute(ctx, rec, body)
		} else {
			err = fmt.Errorf("capability %q: no executor registered for type %q", capabilityID, rec.ExecutorType)
		}
	} else {
		inv := m.invoker
		if inv == nil {
			inv = &httpInvoker{mgr: m}
		}
		res, err = inv.Invoke(ctx, caller, provider.ID, capabilityID, body)
	}
	if err != nil {
		m.log.RecordInvocationDetail(caller, capabilityID, executorType, body, "error", start,
			activitylog.EventDetail{IntentEventID: intentID, StatusReason: "executor: " + err.Error()})
		return nil, err
	}
	out := auth.FilterEgress(ctx, caller, capDef, res)
	status := "ok"
	detail := activitylog.EventDetail{IntentEventID: intentID}
	if out != nil {
		// ResultHash is taken from the FILTERED body — the bytes the caller actually
		// received. Hashing the pre-filter result would commit to something no party
		// ever saw, and would put egress-stripped data back into the record by proxy.
		detail.ResultBody = out.Body
		if out.Status >= 400 {
			status = "error"
			detail.StatusReason = fmt.Sprintf("capability returned HTTP %d", out.Status)
		}
	}
	eventID := m.log.RecordInvocationDetail(caller, capabilityID, executorType, body, status, start, detail)
	if out != nil {
		out.AuditEventID = eventID
	}
	return out, nil
}

// findProvider resolves which installed plug-in offers a capability.
//
// ONE PROVIDER OR NONE. Loading refuses a second app declaring an id already
// provided (LoadManifests), and this refuses again rather than choosing: the
// manifests are a map, so "the first one found" is whichever the runtime
// happens to iterate to, and an app that answered a capability it had copied
// would receive that capability's callers, stamped as genuine. A plug-in id
// that a registry-native capability also has is refused the same way, since
// the plug-in would otherwise silently shadow it.
func (m *Manager) findProvider(capabilityID string) (*AppManifest, ProvidedCapability, bool) {
	manifest, capDef, err := m.theOneProvider(capabilityID)
	if err != nil || manifest == nil {
		return nil, ProvidedCapability{}, false
	}
	return manifest, capDef, true
}

// ErrAmbiguousProvider is a capability id declared by more than one provider.
var ErrAmbiguousProvider = errors.New("more than one provider declares this capability")

// theOneProvider is findProvider saying why it found none: nil and no error
// when nothing provides it, ErrAmbiguousProvider when more than one does.
func (m *Manager) theOneProvider(capabilityID string) (*AppManifest, ProvidedCapability, error) {
	m.mu.RLock()
	var found *AppManifest
	var capDef ProvidedCapability
	count := 0
	for _, manifest := range m.manifests {
		for _, p := range manifest.Provides {
			if p.ID == capabilityID {
				found, capDef = manifest, p
				count++
			}
		}
	}
	m.mu.RUnlock()
	if count == 0 {
		return nil, ProvidedCapability{}, nil
	}
	if count > 1 || m.registryRecord(capabilityID) != nil {
		return nil, ProvidedCapability{}, fmt.Errorf("%w: %q", ErrAmbiguousProvider, capabilityID)
	}
	return found, capDef, nil
}

// httpInvoker routes to the running plug-in's local capability API (the plug-in SDK's
// POST /v1/capability/{id} on the instance's display port), stamped with who
// called under the app's own key.
type httpInvoker struct{ mgr *Manager }

func (h *httpInvoker) Invoke(ctx context.Context, caller permission.CallerContext, appID, capabilityID string, body []byte) (*InvokeResult, error) {
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
	url := fmt.Sprintf("http://127.0.0.1:%d/v1/capability/%s", *inst.DisplayPort, neturl.PathEscape(capabilityID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// No call leaves without saying who made it. An app that cannot be told
	// would have to trust whatever reached its port, so a key that cannot be
	// had stops the call rather than sending it unstamped.
	key, err := h.mgr.AppCallKey(appID)
	if err != nil {
		return nil, fmt.Errorf("the call to %q could not be stamped: %w", appID, err)
	}
	if err := appcall.Stamp(req.Header, key, capabilityID, body, theCallerAnAppIsTold(caller), time.Now()); err != nil {
		return nil, fmt.Errorf("the call to %q could not be stamped: %w", appID, err)
	}
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
