package sandbox

import (
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/permission"
)

// passesTheOneCheck is MayThisPersonDoThis for a capability invocation: the
// caller's score, from the placeholder until human authentication is built,
// against the capability's minimum. Invoking, listing and describing all ask
// it, so discovery never offers a capability the caller would be refused.
func passesTheOneCheck(caller permission.CallerContext, capDef ProvidedCapability, now time.Time) (bool, string) {
	return permission.MayThisPersonDoThis(
		permission.Action{Name: capDef.ID, MinimumScore: capDef.MinimumScore},
		permission.Person{AID: caller.CallerAID, Authenticated: authprovider.UntilHumanAuthenticationIsBuilt(now)},
	)
}
