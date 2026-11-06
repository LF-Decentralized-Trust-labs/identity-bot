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
// rootSeedRefusalTitle is the headline of every answer that says this computer
// cannot hold a root seed.
const rootSeedRefusalTitle = "an identity cannot be created on this computer"

// refuseIfRootSeedRefused answers 412 with the refusal body when err is the
// root-seed refusal, and reports whether it did.
//
// The refusal comes out of ensureRootSeed on any path that needs key material
// (pairing a non-root computer, minting an owner or pairwise identity). Left to
// each caller's own error branch it surfaced as an untyped 500 or 503, which a
// client cannot tell from a fault. Same status and body as
// refuseIfThisComputerMayNotFound, so a client handles one shape.
func refuseIfRootSeedRefused(w http.ResponseWriter, err error) bool {
	if !secureenclave.IsRootSeedRefusal(err) {
		return false
	}
	writeError(w, http.StatusPreconditionFailed, rootSeedRefusalTitle, err.Error())
	return true
}

func (s *CoreServer) refuseIfThisComputerMayNotFound(w http.ResponseWriter) bool {
	v := secureenclave.MayFoundAnIdentityHere(s.DataDir)
	if secureenclave.FoundingPermitted(v, buildmode.IsDev()) {
		// WHERE IT RUNS IS NOT ENOUGH; THE ROOT SEED HAS TO BE ABLE TO BE
		// PROTECTED TOO. A phone always passes the question above and can still
		// have no wrapper for the seed (an app that registers none), and founding
		// there would write the person's root as a plain file. The same check
		// handleSetRootSeed, StoreIdentityRootSeed and recovery make, asked here
		// so every way of founding makes it, before anything is generated.
		// A development build passes it, and says so in ReportSeedProtection.
		if err := secureenclave.CheckRootSeedMayLiveHere(s.DataDir); err != nil {
			writeError(w, http.StatusPreconditionFailed, rootSeedRefusalTitle, err.Error())
			return true
		}
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
