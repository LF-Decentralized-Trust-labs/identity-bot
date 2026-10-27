package sandbox

import (
	"fmt"
	"slices"
	"time"
)

// A capability can be a service an AI agent's body performs for this
// Identity Agent, rather than an action the gateway carries out or a
// credential it lends: making machines for other AI agents, say. Nothing
// invokes it. The Identity Agent hands the work only to a body whose AI agent
// holds the capability, and only after the same one check an invocation
// passes.

// ExecutorBodyService is the executor type of a capability that is work an AI
// agent's body does for the Identity Agent.
const ExecutorBodyService = "body_service"

// MayServe is the one check for a body service: the capability is one this
// Identity Agent offers as a body service and has enabled, the caller's grant
// gives it, and the caller passes MayThisPersonDoThis against its minimum. It
// says why when it refuses.
func (m *Manager) MayServe(caller CallerContext, capabilityID string) (bool, string) {
	rec := m.registryRecord(capabilityID)
	switch {
	case rec == nil:
		return false, fmt.Sprintf("%s is not offered by this Identity Agent, or is turned off", capabilityID)
	case rec.ExecutorType != ExecutorBodyService:
		return false, fmt.Sprintf("%s is not work this Identity Agent hands to a body", capabilityID)
	case !slices.Contains(caller.Scopes, capabilityID):
		why := fmt.Sprintf("this AI agent's grant does not give %s", capabilityID)
		if caller.NoScopesBecause != "" {
			why += " (" + caller.NoScopesBecause + ")"
		}
		return false, why
	}
	return passesTheOneCheck(caller, rec.asProvidedCapability(), time.Now())
}
