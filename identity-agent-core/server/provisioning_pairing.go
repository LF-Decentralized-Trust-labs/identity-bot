package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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
	// There is deliberately no adoption code in this struct.
	//
	// There used to be, and it was the whole defect. The comment above it said
	// the code was read once and handed only to whoever provisioned the box —
	// but nothing implemented reading it once, and this response is served to
	// anyone who asks. So the secret that decided who owned the box was handed
	// to whoever reached it first, which on a reachable address is a stranger.
	//
	// The box is now TOLD which token to expect, before it can be reached, by
	// whoever provisioned it (see expectedClaim / handleProvisioningExpect). It
	// never mints one and never publishes one. What stays here is what a caller
	// genuinely needs and what discloses nothing: the pairwise AID it is about
	// to publish anyway, and an attestation of what this box is.
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
	offer, err := newPairingOffer(aid, oobi)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Could not offer pairing", err.Error())
		return
	}

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

// newPairingOffer builds the offer an instance publishes.
func newPairingOffer(aid, oobi string) (*pairingOffer, error) {
	return &pairingOffer{AID: aid, OOBI: oobi}, nil
}

func writePairingOffer(w http.ResponseWriter, offer *pairingOffer) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(offer)
}

// expectedClaim is what this box has been told to expect, and from whom.
//
// Set once, by whoever provisioned it, during the window before it can be
// reached from anywhere else. Never minted here and never served.
var expectedClaim struct {
	sync.Mutex
	token    string
	ownerAID string
	set      bool
}

// SetExpectedClaim tells this instance which claim it will accept.
//
// First write wins, deliberately. Whoever provisioned the box says this while
// it is still reachable only from the host that started it; a caller arriving
// later, from anywhere else, must not be able to point it at a claim of their
// own.
func SetExpectedClaim(token, ownerAID string) error {
	if token == "" || ownerAID == "" {
		return fmt.Errorf("a claim expectation needs both a token and the AID it will be presented by")
	}
	expectedClaim.Lock()
	defer expectedClaim.Unlock()
	if expectedClaim.set {
		return fmt.Errorf("this instance has already been told what to expect")
	}
	expectedClaim.token, expectedClaim.ownerAID, expectedClaim.set = token, ownerAID, true
	return nil
}

// expectedAdoption returns the claim this box will accept.
//
// An empty token means nobody has told it, and adoption must refuse rather than
// fall back to something guessable. Refusing is the safe direction: a box
// nobody can claim is recoverable, a box anybody can claim is not.
func expectedAdoption() (token, ownerAID string, told bool) {
	expectedClaim.Lock()
	defer expectedClaim.Unlock()
	return expectedClaim.token, expectedClaim.ownerAID, expectedClaim.set
}

// resetPairingOfferForTest lets tests start from a clean slate; the offer is
// process-wide by design, since an instance offers itself exactly once.
func resetPairingOfferForTest() {
	pairingOnce.Lock()
	defer pairingOnce.Unlock()
	pairingOnce.offer = nil
}

// handleProvisioningExpect tells this instance which claim it will accept.
//
// This is for a black box (ADR-006): a computer the owner does not physically
// hold. The owner is not at the keyboard, so the box cannot simply trust
// whoever reaches it first. Whoever provisioned it says in advance who to
// expect.
//
// Called while the box is still reachable only from the host that started it,
// before it is published anywhere. That window is the protection, together with
// first-write-wins: a caller arriving later cannot point the box at a claim of
// their own.
//
// It carries no authentication because there is nobody to authenticate yet. A
// box at this point has no identity, no owner and no sealed key, so there is no
// signature it could check and nothing to check one against. Saying that
// plainly is better than inventing a credential that would have to ship inside
// the image and would therefore be identical in every box.
//
// THE RESIDUAL, stated rather than glossed: anybody who can reach the box
// during that window, before it has been told, can tell it themselves. Keeping
// the window closed is the job of whatever starts it — set the expectation
// first, publish second. A box that is reachable from the moment it boots has
// no protection here, and must be told before it is reachable at all.
func (s *CoreServer) handleProvisioningExpect(w http.ResponseWriter, r *http.Request) {
	if s.DataStore != nil {
		if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
			writeError(w, http.StatusConflict, "Already paired",
				"this instance has an identity; what it would accept no longer matters")
			return
		}
	}

	var body struct {
		ClaimToken string `json:"claim_token"`
		OwnerAID   string `json:"owner_aid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if err := SetExpectedClaim(body.ClaimToken, body.OwnerAID); err != nil {
		// Both failures are the caller's, and they are different: one is a
		// malformed request, the other is arriving second.
		if strings.Contains(err.Error(), "already been told") {
			writeError(w, http.StatusConflict, "Already told", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "Incomplete claim expectation", err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
