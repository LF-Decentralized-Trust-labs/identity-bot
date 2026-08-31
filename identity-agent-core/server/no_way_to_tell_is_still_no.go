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
	// An app that never told us. Android only: the Keystore is a Java API the
	// core cannot reach, so the app probes it and reports — and one that stays
	// quiet is indistinguishable from one that looked and found nothing.
	//
	// It gets its own branch because the default below says "this machine was
	// checked", which is false here, and then asks the person to report their
	// platform — when the platform is supported and the fix is a line of wiring
	// in whatever app is embedding the core. Sending somebody to file a report
	// about their phone for a mistake in our code is the failure this whole
	// file is about, aimed at the wrong target.
	case cap.Reason == "app_did_not_report_key_protection":
		msg = "this app did not tell the agent what protects a key on this device, so " +
			"nothing is known about it. That is a gap in the app rather than in the " +
			"device: it must probe the keystore and report what it found before the " +
			"agent starts. An identity may not be founded on a maybe."

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

	// The detector's own words, when it had any.
	//
	// Every detector was written to put the actionable part in Detail — which
	// firmware setting, which group, that the module needs provisioning — and
	// refusalFor used only cap.String(), which renders Status, Kind and Reason
	// and never Detail. So the one sentence that told somebody what to DO was
	// composed, carried across a process boundary, and dropped at the last
	// step, leaving a generic guess in its place.
	if cap.Detail != "" {
		msg += " The check reported: " + cap.Detail + "."
	}

	// Only for what we could not classify, and not for an app that never asked
	// — that one has an answer already and a report would not add to it.
	if cap.Status == secureenclave.Unknown && cap.Reason != "app_did_not_report_key_protection" {
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
		return "This machine produced an answer this build does not recognise. If you " +
			"would like it supported, report it at " + url + " and include: " + env + "."
	}
	return "This machine produced an answer this build does not recognise. If you would " +
		"like it supported, report it to whoever maintains this software and include: " +
		env + "."
}
