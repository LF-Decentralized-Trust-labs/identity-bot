package login

import (
	"fmt"

	"identity-agent-core/backendaddr"
	"identity-agent-core/buildmode"
)

// The kinds of front end a sign-in to a utility app can name (ADR-072 section 3).
const (
	FrontEndBrowser      = "browser"
	FrontEndInstalledApp = "installed_app"
)

// CheckFrontEnd refuses a front-end kind that is not one of the two, and
// accepts "" (a challenge that names none). The person's agent runs it on the
// signed challenge before showing consent, and a verifier runs it on the kind
// it expects.
func CheckFrontEnd(kind string) error {
	switch kind {
	case "", FrontEndBrowser, FrontEndInstalledApp:
		return nil
	}
	return fmt.Errorf("a sign-in names a front end that is not 'browser' or 'installed_app'")
}

// inDev says whether this is a development build, which may name a back end on
// this machine. A variable so a test can say it is.
var inDev = buildmode.IsDev

// CheckUtilityAppAddress checks the relay identifier and the back-end address a
// signed challenge names for a utility app, before the person is asked and before
// either is kept (a person's Identity Agent keeps both with a browser sign-in, to
// know where to send the end of a session). A challenge that names neither passes:
// those are for something that is not a utility app. What it names must be one
// the shared rule accepts (package backendaddr), so a site cannot have the end of
// a session sent to an address inside the person's own network or to this machine.
func CheckUtilityAppAddress(c *ChallengeBundle) error {
	if c.RelayID != "" {
		if err := backendaddr.CheckRelayID(c.RelayID); err != nil {
			return fmt.Errorf("a sign-in names a relay identifier this agent will not keep: %w", err)
		}
	}
	if c.BackEnd != "" {
		if err := backendaddr.Check(c.BackEnd, inDev()); err != nil {
			return fmt.Errorf("a sign-in names a back-end address this agent will not keep: %w", err)
		}
	}
	return nil
}
