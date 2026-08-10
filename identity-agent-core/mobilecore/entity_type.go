package mobilecore

import (
	"fmt"
	"os"
)

// Declaring whether this app serves a person or an organization.
//
// The core is the same code inside every app and cannot tell which one it is
// running in. An app built for individuals can, absolutely — an organization
// cannot be founded in it — so the app says so, here, before the server starts.
//
// It decides who may witness and watch for this agent: peers are of the same
// kind, and an agent that does not know what it is enrols no peers at all.
//
// An app that genuinely serves both — the reference Identity Agent asks during
// onboarding — declares nothing and the profile answers instead. That is a
// supported arrangement rather than a missing call; what is not supported is an
// app that knows and stays quiet.
//
// Must be called before StartServer. Afterwards it has no effect, because the
// server has already read it.
func DeclareEntityType(kind string) error {
	switch kind {
	case "individual", "organization":
		return os.Setenv("IDENTITY_AGENT_ENTITY_TYPE", kind)
	default:
		return fmt.Errorf("%q is neither individual nor organization; an app that serves "+
			"both should declare nothing and let the profile answer", kind)
	}
}
