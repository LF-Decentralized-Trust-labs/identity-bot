package server

import (
	"errors"
	"fmt"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"

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
func (s *CoreServer) localRevocationState(cred *keri.Credential) revocationState {
	if cred == nil {
		return revocationState{status: revocationNoRegistryState}
	}
	said, registry := cred.SAID, cred.Registry
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

// errCredentialUnreadable is returned where the credential's bytes cannot be
// read. A credential this agent cannot read is refused, never passed on to be
// judged by something that might read it differently.
var errCredentialUnreadable = errors.New("the credential cannot be read")

// readCredentialHere reads a credential exactly as the engine does: base64 in
// any spelling the engine accepts (iacrypto.DecodeBase64), then the bytes
// checked against their own identifier (keri.VerifyCredential). The credential
// id, the issuer and the registry used for the revocation check come from this
// and from nothing else, so they are the ones the engine is judging. A second,
// differently-spelled decode is how a credential this agent revoked was once
// read as "no registry state held".
func readCredentialHere(acdcB64 string) (*keri.Credential, error) {
	raw, err := iacrypto.DecodeBase64(acdcB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCredentialUnreadable, err)
	}
	cred, err := keri.VerifyCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCredentialUnreadable, err)
	}
	return cred, nil
}

// verifyCredentialHere is the one way this agent asks the engine to verify a
// credential. Every path that verifies a credential or a presentation of one
// goes through it, so a credential revoked here cannot verify anywhere here:
// it supplies the credential's transaction log where this agent holds the
// registry, and folds what that shows into the engine's verdict.
//
// cred is the credential as readCredentialHere read it. Without one there is
// nothing to check a revocation against, and the credential is refused.
func (s *CoreServer) verifyCredentialHere(req *drivers.DriverVerifyCredentialRequest, cred *keri.Credential) (verifyReply, error) {
	if cred == nil {
		return verifyReply{}, errCredentialUnreadable
	}
	revocation := s.localRevocationState(cred)
	// The caller may supply the credential's log as kept here (its issuer's
	// events) for the proof of issuance. It is used only where this agent holds
	// no registry state of its own, and only to learn of a revocation: a kept
	// log may be partial, and nothing here proves it holds every event its
	// issuer sealed, so it never makes a credential read "not revoked", and
	// never overrides what this agent's own record says.
	supplied := req.RegistryEventsB64
	if revocation.status == revocationNoRegistryState && len(supplied) > 0 {
		req.RegistryEventsB64 = supplied
	} else {
		req.RegistryEventsB64 = revocation.log
	}
	res, err := s.KeriDriver.VerifyCredential(req)
	if err != nil {
		return verifyReply{}, err
	}
	if revocation.status == revocationNoRegistryState && len(supplied) > 0 && res != nil {
		if notRevoked, ok := res.Checks["not_revoked"].(bool); ok && !notRevoked {
			revocation = revocationState{log: supplied, status: revocationRevoked,
				reason: "the credential has been revoked by its issuer"}
		}
	}
	return revocation.applyTo(res), nil
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
