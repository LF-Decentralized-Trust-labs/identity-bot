package server

import "net/http"

// Whether an identity may be brought into being on THIS machine.
//
// THE QUESTION IS NOT WHETHER A KEY CAN BE PROTECTED HERE. That one has its own
// answer — RootKeyPermitted — and asking it instead is how a laptop came to
// found root identities. A Mac has a Secure Enclave, so it passes; and it still
// cannot tell anybody what software is using that key.
//
// The question is whether this machine can PROVE WHAT SOFTWARE IT RUNS to
// somebody who is not sitting at it. An identity is a claim other people rely
// on, and the software holding its keys is the thing that decides what it says.
// A machine that cannot prove what it is running is asking to be taken on
// trust, and there is no way to withdraw that trust later because there was
// never anything to check.
//
// Three platforms can do it: iOS and Android, whose vendors attest the running
// application, and an AMD SEV-SNP sealed machine, which attests the whole guest.
// Nothing else — not macOS, where the attestation API reports unsupported and
// carrying its entitlement makes the application unlaunchable; not Windows,
// which has no mechanism for an ordinary user-mode application; not desktop
// Linux, which cannot do it for software distributed to the public.
//
// BEING REFUSED HERE IS NOT BEING REFUSED THE SOFTWARE. Any machine may run
// this application as a controller for an identity that lives somewhere it can
// be proved, and as somewhere backups are kept. This governs one thing: where
// an identity is allowed to begin.

// whereAnIdentityMayBeFounded reports whether this machine may found one, and
// says why not when it may not.
//
// The reason is returned rather than logged because it is shown to a person who
// has just been stopped from doing the obvious thing, and "no" without "and
// here is what to do instead" is how somebody concludes the software is broken.
type foundingVerdict struct {
	Permitted bool   `json:"permitted"`
	Platform  string `json:"platform"`
	Why       string `json:"why,omitempty"`
	// Instead names what this machine CAN do, so the refusal ends somewhere.
	Instead string `json:"instead,omitempty"`
}

const cannotProveItsSoftware = "this computer cannot prove to anybody else " +
	"what software it is running, so an identity founded here could never be " +
	"checked by the people relying on it"

const actForOneInstead = "it can act for an identity kept on a machine that " +
	"can prove itself, and it can hold backups"

// mayFoundAnIdentityHere is the one place that decides.
//
// Per-platform in the files beside this one, the same way enclave detection is,
// because the honest answer differs by operating system and a single function
// full of build tags is where the two get confused.
//
// A var so a test can stand in for the platform, the same way the seed wrapper
// is. Everything that founds an identity has to run somewhere, and the machines
// this is written to refuse are the machines it is developed on — so without
// this, the only tests that could exercise founding would be the ones nobody
// can run.
var mayFoundAnIdentityHere = foundingVerdictForThisPlatform

// refuseIfThisComputerMayNotFound writes the refusal and reports whether it did.
//
// EVERY WAY IN GOES THROUGH THIS. A gate on one route out of several is worse
// than no gate, because it reads as closed: somebody adds a second path, nobody
// notices it was never covered, and the first one goes on looking like the
// answer. There is more than one way to bring an identity into being here and
// they do not resemble each other — founding directly, a computer founding its
// own root as it is paired, a recovery minting a new one, and storing one
// somebody else made.
//
// Placed before anything is read or generated, so a machine that may not found
// never produces key material it would then have to throw away.
func (s *CoreServer) refuseIfThisComputerMayNotFound(w http.ResponseWriter) bool {
	v := mayFoundAnIdentityHere()
	if v.Permitted {
		return false
	}
	// Joined rather than concatenated, so a verdict written without an "instead"
	// cannot produce a sentence trailing off after a dash. The shape is asserted
	// in a test as well; this is what stops it reaching anybody meanwhile.
	detail := v.Why
	if v.Instead != "" {
		detail = v.Why + " — " + v.Instead
	}
	writeError(w, http.StatusForbidden,
		"an identity cannot be created on this computer", detail)
	return true
}
