package secureenclave

// Turning what an app reported into a Capability this package will stand behind.
//
// Separated from the Android-only storage so it can be tested on any host. The
// logic is small and the failure it prevents is not: a status this core does not
// understand must never be stored and later asserted, because everything
// downstream — including whether somebody's root key may live on their phone —
// reads that value and cannot tell it came from outside.
func normaliseDeclaredCapability(status, kind, reason, detail string) Capability {
	c := Capability{
		Status: Status(status),
		Kind:   Kind(kind),
		Reason: reason,
		Detail: detail,
	}
	switch c.Status {
	case Usable, Present, Absent, Unknown:
		return c
	default:
		// A newer app talking to an older core. It must not be able to make the
		// core assert something it does not understand, and the honest version
		// of "I do not understand this" is Unknown — not a rejection, and
		// certainly not Absent.
		return Capability{
			Status: Unknown,
			Reason: "unrecognised_status_from_app",
			Detail: "the app reported a status this core does not know: " + status,
		}
	}
}
