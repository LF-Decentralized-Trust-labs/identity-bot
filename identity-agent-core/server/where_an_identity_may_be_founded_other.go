//go:build !ios && !android && !darwin && !windows && !linux

package server

import "runtime"

// Anything this build was not written for. Refused, because the whole point of
// the question is that being unable to answer it is not permission — an
// identity founded on a machine nobody has established anything about is the
// one failure that cannot be undone afterwards.
func foundingVerdictForThisPlatform() foundingVerdict {
	return foundingVerdict{
		Permitted: false,
		Platform:  runtime.GOOS,
		Why: "nothing is known about what this computer can prove, and an " +
			"identity may not be founded on a machine nobody has established " +
			"anything about",
		Instead: actForOneInstead,
	}
}
