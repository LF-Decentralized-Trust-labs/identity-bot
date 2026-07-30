package sandbox

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// An Executor turns an authorized invocation into an effect.
//
// The registry can describe far more kinds of capability than the engine ships
// code for. Before this seam existed, a record whose executor type was anything
// other than external_api reached dispatch and stopped there — so a caller could
// be granted a capability the engine was structurally unable to exercise, and the
// only way to add a new kind was to fork the engine.
//
// This is the executor counterpart to SetAuthorizer and SetEventSigner: the engine
// owns the pipeline — authorization, per-grant resource constraints, host-control
// serialization, signed audit — and a deployment supplies the part that actually
// acts. An executor is reached only after every one of those checks has passed, so
// an implementation is responsible for performing the effect safely, not for
// deciding whether it was allowed.
//
// Implementations must treat the record as the trusted input and the arguments as
// the untrusted one. A caller supplies arguments; it must never be able to supply
// the effect.
type Executor interface {
	// Execute performs the invocation described by rec with the caller's arguments.
	//
	// An effect that runs and fails on its own terms — a non-zero exit, a rejected
	// request — should be reported in the result, not returned as an error. Reserve
	// the error return for the invocation being impossible: a malformed record,
	// unreachable machinery. The distinction matters to callers, who can react to
	// the first and only retry or escalate on the second.
	Execute(ctx context.Context, rec *CapabilityRecord, args []byte) (*InvokeResult, error)
}

// builtinExecutorTypes are the types the engine either implements itself or
// reserves. They are always valid in a pack, whether or not an executor is
// registered for them.
var builtinExecutorTypes = map[string]bool{
	"internal_api": true,
	"external_api": true,
	"ai_agent":     true,
	"host_control": true,
	"plugin":       true,
}

var (
	executorMu       sync.RWMutex
	registeredExecs  = map[string]Executor{}
	executorNameRule = "lowercase letters, digits and underscores"
)

// RegisterExecutor installs an executor for an executor type, and makes that type
// valid in capability packs.
//
// It is called at startup, before the manager begins serving. Registering the same
// name twice is an error rather than a silent replacement: two components each
// believing they own an executor type is a bug worth surfacing loudly, and the
// alternative makes behaviour depend on initialization order.
func RegisterExecutor(name string, e Executor) error {
	if e == nil {
		return fmt.Errorf("executor %q: implementation is nil", name)
	}
	if !validExecutorName(name) {
		return fmt.Errorf("executor name %q is invalid: expected %s", name, executorNameRule)
	}
	if builtinExecutorTypes[name] {
		return fmt.Errorf("executor %q is a built-in type and cannot be replaced", name)
	}
	executorMu.Lock()
	defer executorMu.Unlock()
	if _, exists := registeredExecs[name]; exists {
		return fmt.Errorf("executor %q is already registered", name)
	}
	registeredExecs[name] = e
	return nil
}

// executorFor returns the executor registered for a type, or nil.
func executorFor(name string) Executor {
	executorMu.RLock()
	defer executorMu.RUnlock()
	return registeredExecs[name]
}

// knownExecutorType reports whether a pack may declare this executor type: either
// the engine reserves it, or a deployment has registered an executor for it.
func knownExecutorType(name string) bool {
	if builtinExecutorTypes[name] {
		return true
	}
	executorMu.RLock()
	defer executorMu.RUnlock()
	_, ok := registeredExecs[name]
	return ok
}

// RegisteredExecutorTypes lists the registered executor types, sorted. Useful for
// diagnostics and for telling an operator why a pack was rejected.
func RegisteredExecutorTypes() []string {
	executorMu.RLock()
	defer executorMu.RUnlock()
	out := make([]string, 0, len(registeredExecs))
	for k := range registeredExecs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// unregisterExecutorsForTest clears the registry. Test-only: the registry is
// process-global by design, because executor types are a global taxonomy that pack
// parsing validates against, and pack parsing has no manager to consult.
func unregisterExecutorsForTest() {
	executorMu.Lock()
	defer executorMu.Unlock()
	registeredExecs = map[string]Executor{}
}

func validExecutorName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return !strings.HasPrefix(name, "_")
}
