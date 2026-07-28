package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"identity-agent-core/secureenclave"
)

// How a freshly provisioned instance offers itself for pairing.
//
// An agent that has just been started by an infrastructure provider is in an
// unusual state: it has no identity, and it has no owner. It cannot be given
// either one remotely — a provider that could hand an instance its keys would
// be a provider that had them, and a provider that could name the owner would
// be the owner. So the instance does the only thing it can do for itself: it
// mints a pairwise AID, publishes it, and waits for somebody to pair.
//
// That AID is what the provisioning service reads back and hands to the user as
// an OOBI. The instance mints it; the provider only reads it. Reversing that
// order would give away the whole trust model.

type pairingOffer struct {
	AID  string `json:"aid"`
	OOBI string `json:"oobi"`
	// Attestation is the guest's SEV-SNP report, base64, present only when this
	// instance is running in a sealed VM that can produce one. Absent is a real
	// answer — it means nobody can verify what this box is — and a caller that
	// requires sealed infrastructure must treat absence as a failure rather
	// than as an older version being lenient.
	Attestation string `json:"attestation,omitempty"`
	// AttestationBinding names what the report's REPORT_DATA is bound to, so a
	// verifier can recompute it rather than trust the pairing.
	AttestationBinding string `json:"attestation_binding,omitempty"`
	// AdoptionCode is generated here, by the instance, and must be presented to
	// complete an adoption.
	//
	// The box URL alone cannot be the only thing standing between a stranger
	// and an unadopted instance. It travels through a browser, a page, a link
	// and possibly a screenshot, and whoever reaches an unadopted box first
	// wins it. The code never appears in the URL: the provisioning service
	// reads it once, hands it to whoever provisioned, and nobody who merely
	// learns the address can use it.
	//
	// The two answer different questions, and an instance needs both: the
	// attestation says what this box is, the code says it is yours. Proving
	// the hardware is sealed is no use if a stranger has already claimed it.
	AdoptionCode string `json:"adoption_code,omitempty"`
}

var pairingOnce struct {
	sync.Mutex
	offer *pairingOffer
}

// handleProvisioningPairing returns the pairwise AID this instance minted for
// pairing, minting it on the first call.
//
// It is deliberately reachable without authorisation, and it is the only
// endpoint on the agent that is. The reasoning has to hold, so: it runs only
// while the instance has no identity and no owner, it discloses a pairwise AID
// that is about to be published as an OOBI anyway, and it discloses nothing
// else — no root AID, no key, no profile, nothing about a person. Once the
// instance has been paired it stops answering, because by then there is an
// owner and this is no longer the only way in.
func (s *CoreServer) handleProvisioningPairing(w http.ResponseWriter, r *http.Request) {
	// Already has an identity? Then it has been paired, and an unauthenticated
	// caller has no business here any more.
	if s.DataStore != nil {
		if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
			writeError(w, http.StatusConflict, "Already paired",
				"this instance has an identity; pairing is offered only before one exists")
			return
		}
	}

	pairingOnce.Lock()
	defer pairingOnce.Unlock()

	// Mint once. A second call must return the same AID, or a provisioning
	// retry would hand the user a different box than the one it described.
	if pairingOnce.offer != nil {
		writePairingOffer(w, pairingOnce.offer)
		return
	}

	aid, oobi, _, err := s.mintPairwise("provisioning-pairing")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Could not offer pairing", err.Error())
		return
	}
	offer := &pairingOffer{AID: aid, OOBI: oobi}

	// Bind the attestation to the AID we just minted. A report that only says
	// "some sealed guest ran the right image" is satisfied by any instance
	// anywhere, including the provider's own; bound to this AID it says "the
	// guest that minted THIS identity ran the right image", which is the claim
	// somebody pairing actually needs.
	if secureenclave.SNPAvailable() {
		if report, rerr := secureenclave.GetSNPReport(aid); rerr == nil {
			offer.Attestation = base64.StdEncoding.EncodeToString(report.Raw)
			offer.AttestationBinding = "blake3-256(IA-SNP-BIND-V1\\n" + aid + ")"
		} else {
			// Being in a sealed VM and failing to prove it is worth saying out
			// loud: it is the case where the box is fine but nobody can tell.
			log.Printf("[provisioning] SNP guest present but no report available: %v", rerr)
		}
	}
	pairingOnce.offer = offer
	writePairingOffer(w, pairingOnce.offer)
}

func writePairingOffer(w http.ResponseWriter, offer *pairingOffer) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(offer)
}

// newAdoptionCode mints the one-time code that gates adoption.
func newAdoptionCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("no source of randomness for an adoption code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// expectedAdoptionCode returns the code this instance is waiting for, if it has
// offered itself for pairing at all.
func expectedAdoptionCode() string {
	pairingOnce.Lock()
	defer pairingOnce.Unlock()
	if pairingOnce.offer == nil {
		return ""
	}
	return pairingOnce.offer.AdoptionCode
}

// resetPairingOfferForTest lets tests start from a clean slate; the offer is
// process-wide by design, since an instance offers itself exactly once.
func resetPairingOfferForTest() {
	pairingOnce.Lock()
	defer pairingOnce.Unlock()
	pairingOnce.offer = nil
}
