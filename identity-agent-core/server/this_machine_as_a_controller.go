package server

import (
	"fmt"
	"net/http"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// The controller's own half of the ceremony: what this machine offers when it
// asks to act for somebody's identity.
//
// A CONTROLLER'S IDENTIFIER IS ITS KEY. It uses a non-transferable identifier —
// the CESR "B" form, which encodes the public key itself — so there is no
// inception event, no key event log, no witness, and nothing published anywhere.
// That matters more here than anywhere else in the system: the whole reason a
// controller is not a delegated identifier is that a delegated inception names
// its parent to anybody who can reach the machine. An identifier that is simply
// a key names nobody at all.
//
// What it gives up is rotation, and it gives up nothing by giving that up. A
// controller whose key is compromised is not rotated, it is REVOKED — the owner
// removes the grant, and the machine is nobody again. Rotation would buy the
// ability to keep the same identifier across a new key, which is worth having
// for an identity and worthless for a machine that is only ever named in one
// place.
//
// The key never leaves the enclave, which is what makes all of this true. A key
// anybody can copy off is an authorisation granted to anybody, so a machine with
// no enclave cannot be a controller at all — the same rule that stops such a
// machine being an agent.

// ControllerIdentity is what this machine is, as a controller.
type ControllerIdentity struct {
	// AID is the non-transferable identifier: the public key, encoded.
	AID string `json:"aid"`
	// PublicKey is the same key in verification-key form, which is what a grant
	// records and what request signatures are checked against.
	PublicKey string `json:"public_key"`
	// ProtectedBy names the hardware holding the private half, so the person
	// approving this can be told what is actually protecting it.
	ProtectedBy string `json:"protected_by"`
}

// thisMachineAsAController mints or loads this machine's controller key and
// describes what it can offer.
//
// Refuses on hardware that cannot keep a key to itself, rather than falling back
// to a key on disk. A fallback here would be the failure the whole design
// avoids: an authorisation that anybody who can read a file can take.
func (s *CoreServer) thisMachineAsAController() (ControllerIdentity, error) {
	// NewPlatformSigner falls back to a key on disk when there is no hardware,
	// which is right for the callers that just need to sign something and wrong
	// here. UsingHardware is the distinction, and it has to be checked rather
	// than assumed: the fallback is silent by design.
	signer := secureenclave.NewPlatformSigner(s.DataDir)
	if !secureenclave.UsingHardware(signer) {
		return ControllerIdentity{}, fmt.Errorf(
			"this computer has no hardware that can keep a key to itself (%s), so it "+
				"cannot act for an identity — a key anybody can copy off is an "+
				"authorisation granted to anybody",
			secureenclave.HardwareRootStatus().String())
	}
	pub, err := signer.PublicKey()
	if err != nil {
		return ControllerIdentity{}, fmt.Errorf(
			"this computer's secure hardware would not produce a key: %w", err)
	}
	aid := iacrypto.NonTransferableAIDQB64(pub)
	if aid == "" {
		return ControllerIdentity{}, fmt.Errorf("this computer's key could not be named")
	}
	return ControllerIdentity{
		AID:         aid,
		PublicKey:   iacrypto.VerkeyQB64(pub),
		ProtectedBy: signer.Label(),
	}, nil
}

// handleThisMachineAsAController answers what this machine would offer.
//
// Owner-only, like everything unlisted. It is read by the app on this computer
// so it can show the person what to approve, and there is no reason for anybody
// else to be told which key this machine holds.
func (s *CoreServer) handleThisMachineAsAController(w http.ResponseWriter, r *http.Request) {
	id, err := s.thisMachineAsAController()
	if err != nil {
		// 501 rather than 500: nothing is broken, this hardware cannot do it.
		writeError(w, http.StatusNotImplemented,
			"this computer cannot act for an identity", err.Error())
		return
	}
	writeJSON(w, id)
}

// theKeyThisIdentifierNames recovers the key a controller identifier stands for.
//
// The check a grant needs: an identifier that IS a key cannot name a different
// one, so a grant recording identifier X against key Y is a mistake or an
// attempt, and either way what would be admitted afterwards is whatever Y is.
func theKeyThisIdentifierNames(aid string) ([]byte, error) {
	return iacrypto.KeyFromNonTransferableAID(aid)
}
