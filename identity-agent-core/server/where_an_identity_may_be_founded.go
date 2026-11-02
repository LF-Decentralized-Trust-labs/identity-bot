package server

import (
	"log"
	"net/http"

	"identity-agent-core/buildmode"
	"identity-agent-core/secureenclave"
)

// Whether an identity may be brought into being on THIS machine is decided in
// secureenclave.MayFoundAnIdentityHere, the one function founding, installing a
// root seed and recovering all ask. These are the server's names for it.
type foundingVerdict = secureenclave.FoundingVerdict

const (
	cannotProveItsSoftware = secureenclave.CannotProveItsSoftware
	actForOneInstead       = secureenclave.ActForOneInstead
)

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
	v := secureenclave.MayFoundAnIdentityHere(s.DataDir)
	if secureenclave.FoundingPermitted(v, buildmode.IsDev()) {
		if !v.Permitted {
			// Permitted only by the development-build relaxation. Loud on purpose:
			// an identity founded on a machine that cannot attest is exactly what
			// production refuses, so it must never be relied on as a real one. The
			// cross-realm separation that will enforce that lands with its own code.
			log.Printf("[identity-agent-core] *** DEVELOPMENT BUILD *** founding an identity on a machine that cannot attest (%s) — allowed only because this is a development build; this identity must never be relied on as a production identity", v.Platform)
		}
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

// foundingPermitted keeps the server's name for the shared decision.
func foundingPermitted(v foundingVerdict, dev bool) bool {
	return secureenclave.FoundingPermitted(v, dev)
}
