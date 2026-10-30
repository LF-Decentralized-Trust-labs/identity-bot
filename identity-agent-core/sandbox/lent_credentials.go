package sandbox

import (
	"fmt"
	"slices"
	"time"

	"identity-agent-core/permission"
)

// A capability can be a credential lent to an AI agent's body for one run,
// rather than an action the gateway carries out: access to a code repository,
// say. Nothing invokes it. The Identity Agent lends the credential only to a
// body whose AI agent holds the capability, and only after the same one check
// an invocation passes.

// MayBeLent is the one check for a lent credential: the capability is one
// this Identity Agent offers as a lent credential and has enabled, the caller's
// grant gives it, and the caller passes MayThisPersonDoThis against its
// minimum. It says why when it refuses.
func (m *Manager) MayBeLent(caller permission.CallerContext, capabilityID string) (bool, string) {
	rec := m.registryRecord(capabilityID)
	switch {
	case rec == nil:
		return false, fmt.Sprintf("%s is not offered by this Identity Agent, or is turned off", capabilityID)
	case rec.ExecutorType != ExecutorLentCredential:
		return false, fmt.Sprintf("%s is not a credential this Identity Agent lends", capabilityID)
	case !slices.Contains(caller.Scopes, capabilityID):
		why := fmt.Sprintf("this AI agent's grant does not give %s", capabilityID)
		if caller.NoScopesBecause != "" {
			why += " (" + caller.NoScopesBecause + ")"
		}
		return false, why
	}
	return passesTheOneCheck(caller, rec.asProvidedCapability(), time.Now())
}
