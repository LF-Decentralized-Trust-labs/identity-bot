package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// What a controller shows on a screen for the owner to scan.
//
// This is the offline, self-contained half of the ceremony. Unlike an Ask — the
// rails for a transaction between two DIFFERENT identities, which fetches a
// signed document from a pointer — a controller offer is two of one person's own
// devices meeting, so there is no counterparty to fetch from and no reason to be
// online. It travels whole in the QR, the same way pairing a computer does.
//
// It carries a signature, and that is the one thing today's raw offer lacks.
// A bare offer is a public key and a claim; anybody who photographs it can
// present the same bytes later, or to a different owner. Signing binds the key
// to the agent it is offering to act for and to the moment it was made, so a
// captured offer cannot be replayed to another agent or after it goes stale, and
// the timestamp cannot be edited without breaking the signature. The private key
// that signs never leaves the enclave — which is the whole reason a controller
// can be trusted to hold only its own key.
//
// The signature is NOT what authorises the machine. The owner's grant does that,
// and the agent refuses any request the grant does not cover. This proves the
// offer is fresh and really from the holder of the key it names, so the owner is
// approving a live machine rather than a replayed or substituted claim.

// controllerOfferPrefix keeps a controller offer's signed bytes from ever being
// mistaken for a controller REQUEST's signed bytes. Different first line, so one
// can never be replayed as the other.
const controllerOfferPrefix = "grapeid-controller-offer-v1"

// controllerOfferWindow is how long a freshly made offer stays acceptable.
//
// Short, because the offer is scanned off a screen the person is standing in
// front of — a legitimate scan happens in seconds, and a wide window only widens
// the chance to replay one that was photographed.
const controllerOfferWindow = 5 * time.Minute

// canonicalControllerOffer is the exact string a controller signs to offer
// itself, and the exact string an owner's device rebuilds to check it.
//
// Binds the key (so the signature is about this machine), the agent origin (so
// an offer to act for one agent cannot be replayed against another), and the
// timestamp (so a stale offer is refused and the timestamp cannot be moved).
// Newline-separated with a version prefix, the same shape as a request
// signature, so neither can be read as the other.
func canonicalControllerOffer(verkey, agentOrigin, timestamp string) string {
	return strings.Join([]string{
		controllerOfferPrefix, verkey, agentOrigin, timestamp,
	}, "\n")
}

// ControllerOffer is the signed, self-contained offer a controller displays.
type ControllerOffer struct {
	AID         string `json:"aid"`
	PublicKey   string `json:"public_key"`
	ProtectedBy string `json:"protected_by"`
	// AgentOrigin is where the identity this machine offers to act for lives —
	// bound into the signature so the offer cannot be pointed at a different one.
	AgentOrigin string `json:"agent_origin"`
	// Timestamp is when the offer was made, RFC3339, bound into the signature.
	Timestamp string `json:"timestamp"`
	// Signature is over canonicalControllerOffer, by this machine's own key.
	Signature string `json:"signature"`
}

// handleControllerOffer signs and returns this machine's offer for a given
// agent. Owner-only: it is called by the app on this computer to build the QR.
//
//	POST /api/controller/offer  {"agent_origin": "https://…"}
func (s *CoreServer) handleControllerOffer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentOrigin string `json:"agent_origin"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "the request could not be read", err.Error())
		return
	}
	req.AgentOrigin = strings.TrimSpace(req.AgentOrigin)
	if req.AgentOrigin == "" {
		writeError(w, http.StatusBadRequest, "an offer needs an agent to be for",
			"agent_origin is where the identity this machine would act for lives, and the signature binds the offer to it")
		return
	}

	id, err := s.thisMachineAsAController()
	if err != nil {
		writeError(w, http.StatusNotImplemented, "this computer cannot act for an identity", err.Error())
		return
	}

	signer := secureenclave.NewPlatformSigner(s.DataDir)
	if !secureenclave.UsingHardware(signer) {
		writeError(w, http.StatusNotImplemented, "this computer cannot act for an identity",
			"the key that would sign this offer is not held by hardware")
		return
	}
	pub, err := signer.PublicKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "this computer's key could not be read", err.Error())
		return
	}

	// The timestamp is minted here, not taken from the caller, so freshness is
	// this device's own clock rather than something a stale screen could carry.
	timestamp := time.Now().UTC().Format(time.RFC3339)
	sig, err := signer.Sign([]byte(canonicalControllerOffer(id.PublicKey, req.AgentOrigin, timestamp)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "this computer's secure hardware would not sign", err.Error())
		return
	}
	sigQB64, err := iacrypto.MachineSignatureQB64(pub, sig)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "this computer's signature could not be encoded", err.Error())
		return
	}

	writeJSON(w, ControllerOffer{
		AID:         id.AID,
		PublicKey:   id.PublicKey,
		ProtectedBy: id.ProtectedBy,
		AgentOrigin: req.AgentOrigin,
		Timestamp:   timestamp,
		Signature:   sigQB64,
	})
}

// handleVerifyControllerOffer checks a scanned controller offer before an owner
// is asked to approve it. Called by the app on the OWNER's device.
//
// MANDATORY: this is the sole authentication of the offer. A missing, malformed,
// stale, or unverifiable offer is refused here, and the owner is never shown a
// machine to approve. There is no unsigned path.
//
//	POST /api/controller/verify-offer  {aid, public_key, agent_origin, timestamp, signature}
func (s *CoreServer) handleVerifyControllerOffer(w http.ResponseWriter, r *http.Request) {
	var offer ControllerOffer
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&offer); err != nil {
		writeError(w, http.StatusBadRequest, "the offer could not be read", err.Error())
		return
	}
	if err := s.checkControllerOffer(offer, time.Now().UTC()); err != nil {
		// 422: the offer was read but does not hold up. The one refusal the app
		// turns into "this code cannot be trusted", never a silent pass.
		writeError(w, http.StatusUnprocessableEntity, "this offer could not be trusted", err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":           true,
		"aid":          offer.AID,
		"public_key":   offer.PublicKey,
		"protected_by": offer.ProtectedBy,
		"agent_origin": offer.AgentOrigin,
	})
}

// checkControllerOffer verifies an offer's signature, freshness, and internal
// consistency. Every branch is a refusal the owner needs, not a generic error.
func (s *CoreServer) checkControllerOffer(offer ControllerOffer, now time.Time) error {
	if offer.PublicKey == "" || offer.AgentOrigin == "" || offer.Timestamp == "" || offer.Signature == "" {
		return fmt.Errorf("this offer is missing part of itself, so it cannot be checked")
	}

	// The identifier IS the key. An offer whose aid does not name the same key it
	// publishes is either a mistake or an attempt to have one approved while the
	// other is what gets granted.
	if offer.AID != "" {
		fromAID, err := iacrypto.KeyFromMachineIdentifier(offer.AID)
		if err != nil {
			return fmt.Errorf("this offer's identifier is not a machine identifier: %w", err)
		}
		fromKey, err := iacrypto.KeyFromMachineVerkey(offer.PublicKey)
		if err != nil {
			return fmt.Errorf("this offer's key cannot be read: %w", err)
		}
		if string(fromAID) != string(fromKey) {
			return fmt.Errorf("this offer's identifier and key are different keys, so it names one machine and would grant another")
		}
	}

	signedAt, err := time.Parse(time.RFC3339, offer.Timestamp)
	if err != nil {
		return fmt.Errorf("this offer's time is unreadable, so its freshness cannot be judged")
	}
	if diff := now.Sub(signedAt); diff > controllerOfferWindow || diff < -controllerOfferWindow {
		return fmt.Errorf("this offer is older than %s (or from a device with a wrong clock); ask the computer to show a fresh code", controllerOfferWindow)
	}

	ok, err := iacrypto.VerifyMachineSignature(offer.PublicKey, offer.Signature,
		[]byte(canonicalControllerOffer(offer.PublicKey, offer.AgentOrigin, offer.Timestamp)))
	if err != nil {
		return fmt.Errorf("this offer's signature could not be checked: %w", err)
	}
	if !ok {
		return fmt.Errorf("this offer was not signed by the machine it names, so it is not a real offer from that computer")
	}
	return nil
}
