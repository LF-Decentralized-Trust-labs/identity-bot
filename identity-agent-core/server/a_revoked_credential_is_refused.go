package server

import (
	"fmt"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// Revocation statuses reported by credential/verify in "revocation_status".
//
// There are three honest answers and "not revoked" is only one of them:
// the log was read and the credential is live, the log was read and it was
// withdrawn, or no log could be read. The last is never reported as the first.
const (
	revocationNotRevoked = "not_revoked"
	revocationRevoked    = "revoked"
	// revocationNotCheckedPrefix starts every "not checked" status. What
	// follows says why, e.g. "not checked: no registry state held".
	revocationNotCheckedPrefix = "not checked: "
	revocationNoRegistryState  = revocationNotCheckedPrefix + "no registry state held"
)

// revocationState is what this agent knows of a credential's revocation.
type revocationState struct {
	// log is the credential's transaction log, to be handed to the verifier.
	// Empty where this agent holds none.
	log []string
	// status is one of the statuses above.
	status string
	// reason says why, for the statuses that need one.
	reason string
}

// localRevocationState reads the state of a credential's registry where this
// agent holds it: it issued the credential, or keeps its registry. For any
// other credential nothing is supplied and the status says so. Whether an
// unreachable source counts against the credential is a product decision
// (SEAM-13 OQ-3) and is not made here.
func (s *CoreServer) localRevocationState(acdc map[string]interface{}) revocationState {
	said, _ := acdc["d"].(string)
	registry, _ := acdc["ri"].(string)
	if said == "" || registry == "" {
		return revocationState{status: revocationNoRegistryState}
	}
	reg, err := s.DataStore.GetRegistry(registry)
	if err != nil {
		return revocationState{status: revocationNotCheckedPrefix + "the registry could not be read: " + err.Error()}
	}
	if reg == nil {
		return revocationState{status: revocationNoRegistryState}
	}

	log, state, err := s.credentialLog(registry, said)
	if err != nil {
		// A revocation this agent recorded is not undone by a log it cannot
		// now prove: refuse on its own record.
		if rec, _ := s.DataStore.GetCredential(said); rec != nil && (rec.Status == "revoked" || rec.Status == credentialStatusWithdrawing) {
			return revocationState{status: revocationRevoked,
				reason: fmt.Sprintf("this agent recorded the credential as %s", rec.Status)}
		}
		return revocationState{status: revocationNotCheckedPrefix + "the registry state held here cannot be shown: " + err.Error()}
	}
	if state == keri.StatusRevoked {
		return revocationState{log: log, status: revocationRevoked, reason: "the credential has been revoked by its issuer"}
	}
	return revocationState{log: log, status: revocationNotRevoked}
}

// verifyCredentialHere is the one way this agent asks the engine to verify a
// credential. Every path that verifies a credential or a presentation of one
// goes through it, so a credential revoked here cannot verify anywhere here:
// it supplies the credential's transaction log where this agent holds the
// registry, and folds what that shows into the engine's verdict.
//
// acdc is the credential's decoded body (nil where it could not be decoded;
// the engine then refuses it as malformed and the status is "not checked").
func (s *CoreServer) verifyCredentialHere(req *drivers.DriverVerifyCredentialRequest, acdc map[string]interface{}) (verifyReply, error) {
	revocation := s.localRevocationState(acdc)
	req.RegistryEventsB64 = revocation.log
	res, err := s.KeriDriver.VerifyCredential(req)
	if err != nil {
		return verifyReply{}, err
	}
	return revocation.applyTo(res), nil
}

// recordedRevokedHere reports whether this agent's own record says the
// credential with this SAID was revoked (or is being withdrawn), and why. It
// is for the paths that hold no credential bytes to verify, only a claim about
// one: a claim is not evidence against a record this agent made itself.
func (s *CoreServer) recordedRevokedHere(said string) (string, bool) {
	if said == "" || s.DataStore == nil {
		return "", false
	}
	rec, _ := s.DataStore.GetCredential(said)
	if rec != nil && (rec.Status == "revoked" || rec.Status == credentialStatusWithdrawing) {
		return fmt.Sprintf("this agent recorded the credential as %s", rec.Status), true
	}
	return "", false
}

// verifyReply is the credential/verify reply: everything the engine reports,
// plus the revocation status and, when it is not "not_revoked", why.
type verifyReply struct {
	*drivers.DriverVerifyCredentialResponse
	RevocationStatus string `json:"revocation_status"`
	RevocationReason string `json:"revocation_reason,omitempty"`
}

// applyTo folds the revocation state into the engine's verdict. A revoked
// credential is never verified, whatever the engine could read.
func (r revocationState) applyTo(res *drivers.DriverVerifyCredentialResponse) verifyReply {
	if res == nil {
		res = &drivers.DriverVerifyCredentialResponse{Checks: map[string]interface{}{}}
	}
	if r.status == revocationRevoked {
		if res.Checks == nil {
			res.Checks = map[string]interface{}{}
		}
		res.Checks["not_revoked"] = false
		res.Verified = false
		if r.reason != "" && !containsString(res.Errors, r.reason) {
			res.Errors = append(res.Errors, r.reason)
		}
	}
	return verifyReply{DriverVerifyCredentialResponse: res, RevocationStatus: r.status, RevocationReason: r.reason}
}

func containsString(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}
