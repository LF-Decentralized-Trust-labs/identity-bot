package server

import (
	"time"

	"identity-agent-core/authprovider"
)

// A development build takes an unmeasured controller as verified.
//
// A controller reaches a raised action only with a statement, signed by the
// device that holds this identity's root key, saying how well the person at the
// machine was authenticated. The side that MAKES that statement — measuring the
// person, and having the root device sign the result — is not built yet. Until
// it is, nothing can produce a statement, so on every build no controller can
// create an AI agent, mint its token, issue a credential, or reach anything else
// raised to the verified level.
//
// A development build stands in for the missing measurement, and only for that:
//
//   - Only when nothing was measured. A statement that WAS made and vouched for
//     is used as it is, even when it is lower than verified, because a person
//     who was checked and fell short has not been checked "by default".
//   - Never above verified. The actions raised to high — rotating keys, exporting
//     backups, replacing the root seed — stay out of reach, because those are the
//     ones a development identity still needs to protect from a stray controller.
//   - Never in a production build. The mode is compiled in, and a development
//     build's identities sit under a separate trust anchor that a production
//     verifier refuses, so nothing granted here is worth anything outside it.
//   - Never for a closed action, which no level opens.
//
// It is recorded under its own provider name, so anything that reads who was
// checked and how can tell a stand-in from a measurement.
const developmentBuildProvider = "development-build-default"

func whatThisBuildTakesAsMeasured(
	measured authprovider.Result, isDevBuild bool, now time.Time,
) authprovider.Result {
	if !isDevBuild || measured.Measured {
		return measured
	}
	return authprovider.Result{
		Level:    authprovider.LevelVerified,
		Measured: true,
		At:       now.UTC(),
		Provider: developmentBuildProvider,
	}
}
