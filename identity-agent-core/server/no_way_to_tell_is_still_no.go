package server

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"identity-agent-core/secureenclave"
)

// envUnsupportedPlatformURL is where somebody refused for hardware reasons can
// report what they are running.
//
// Configurable rather than fixed, because this software is not tied to whoever
// happens to be operating an instance of it: a deployment points it at its own
// support channel, and an installation that sets nothing simply gets no link.
// Nothing here should assume a particular organisation is on the other end.
const envUnsupportedPlatformURL = "IA_UNSUPPORTED_PLATFORM_URL"

// refusalFor says why this machine may not hold a root key, and what the person
// can do about it.
//
// Three refusals, and they are genuinely different situations. Telling somebody
// their laptop has no security hardware, when the truth is that we never wrote
// the check for their platform, is a false statement about their computer — and
// it sends them to buy hardware they may already have.
//
// None of the three is a maybe. A seed on a machine that cannot protect it is a
// file, and whoever copies that file becomes the identity, undetectably and
// with no rotation possible. But being refused should not be a dead end, so
// each says who owns the problem and what moves it.
func refusalFor(cap secureenclave.Capability) string {
	var msg string
	switch {
	case cap.Status == secureenclave.Absent:
		msg = "this machine has no hardware that can protect a root key, so an identity kept " +
			"here could be copied off it. Put the root on a device that has such hardware and " +
			"pair this machine to it."

	case cap.Status == secureenclave.Present:
		// The remedy is completely different from Absent: the hardware is
		// there, so this is usually fixable by the person in front of it.
		msg = "this machine has hardware that can protect a root key but cannot use it right now (" +
			cap.String() + "). It may need to be enabled, provisioned, or unlocked."

	case strings.Contains(cap.Reason, "not_implemented"):
		// Our gap, and it should be named as ours.
		msg = "this build cannot tell whether this machine can protect a root key, because the " +
			"check for this platform has not been written yet. That is a gap in this software " +
			"rather than a fault in your computer, and an identity may not be founded on a maybe."

	default:
		// We looked and could not establish it. Different from not having
		// looked, and the person deserves to know which happened.
		msg = "this machine was checked and the answer could not be established (" + cap.String() +
			"). An identity may not be founded on a maybe, so this is refused rather than guessed at."
	}

	if cap.Status == secureenclave.Unknown {
		msg += " " + howToReport(cap)
	}
	return msg
}

// howToReport gives somebody a way out of being permanently refused.
//
// Only for the unknown cases. Absent is an answer and a link would not change
// it; unknown is a question, and the only thing that resolves it is somebody
// telling us what they are running so the check can be written or fixed.
//
// The environment summary is included in the message so it can be copied
// straight into a report. Asking somebody to go and find their architecture is
// how a report never gets sent.
func howToReport(cap secureenclave.Capability) string {
	env := fmt.Sprintf("platform %s/%s, detector said %q", runtime.GOOS, runtime.GOARCH, cap.String())
	if url := strings.TrimSpace(os.Getenv(envUnsupportedPlatformURL)); url != "" {
		return "If you would like this platform supported, report it at " + url +
			" and include: " + env + "."
	}
	return "If you would like this platform supported, report it to whoever maintains this " +
		"software and include: " + env + "."
}
