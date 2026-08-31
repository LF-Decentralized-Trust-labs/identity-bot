//go:build android

// What an Android machine can protect a key with — reported by the app, because
// the core cannot ask.
//
// THIS IS THE ONE PLATFORM WHERE THE CORE CANNOT LOOK FOR ITSELF, and it is
// worth being explicit about why rather than leaving it to look like an
// oversight. The Keystore is a Java API. There is no syscall, no device node
// and no C library reachable from Go that answers the question — reaching it
// means crossing into the Android runtime, which is the app's side of the
// boundary and not the core's. macOS asks the Security framework directly and
// Windows asks the platform crypto provider directly; here the app asks and
// says what it found.
//
// The shape is DeclareEntityType's, deliberately, and for the same reason it
// gives: "the core is the same code inside every app and cannot tell which one
// it is running in… what is not supported is an app that knows and stays
// quiet." An app that has probed the Keystore must say so before StartServer.
//
// AN APP THAT SAYS NOTHING GETS UNKNOWN, NOT ABSENT. Silence means nobody
// looked, which is exactly what capability.go's central rule is about: "ABSENT
// MUST BE PROVEN. UNKNOWN IS THE DEFAULT." A missing declaration is our own
// wiring gap and must never be rendered to somebody as a claim about their
// phone.

package secureenclave

import "sync"

var (
	androidMu       sync.RWMutex
	androidReported *Capability
)

// DeclareHardwareKeyProtection records what the app found when it probed the
// Android Keystore. Called through mobilecore before the server starts.
//
// The app is trusted here in the same way it is trusted to name its own entity
// type: it is the same binary, shipped by us, on the other side of a boundary
// the core cannot cross. It is not a claim from a stranger.
//
// A status this package does not recognise is stored as Unknown rather than
// rejected, because a newer app talking to an older core must not be able to
// make the core assert something it does not understand.
func DeclareHardwareKeyProtection(status, kind, reason, detail string) {
	c := normaliseDeclaredCapability(status, kind, reason, detail)
	androidMu.Lock()
	androidReported = &c
	androidMu.Unlock()
}

// DetectCapability returns what the app reported, or an honest Unknown.
func DetectCapability() Capability {
	androidMu.RLock()
	reported := androidReported
	androidMu.RUnlock()

	if reported == nil {
		return Unproven("app_did_not_report_key_protection",
			"the Android Keystore can only be probed from the app, and this app did not "+
				"report a result before starting the core — this says nothing about whether "+
				"the phone has secure hardware")
	}
	return *reported
}

// SealedHostCapable reports whether this machine can launch sealed guests.
// A phone cannot, so this is a plain no rather than an unknown.
func SealedHostCapable() bool { return false }
