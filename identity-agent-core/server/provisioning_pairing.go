package server

import (
	"crypto/subtle"
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
	//
	// "Once" now means once per AGENT, not once per process: an offer published
	// before a restart is read back from disk at startup, so this is the same
	// address it has always published.
	if pairingOnce.offer != nil {
		writePairingOffer(w, s.withAttestation(pairingOnce.offer))
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

	// Written down before it is served, so this agent cannot hand out an address
	// it will not remember. The other order leaves exactly the hole this closes:
	// somebody holding an address that stops resolving at the next restart.
	//
	// The key and the key event log are read back from the registries
	// mintPairwise has just populated, because those two are what make the AID
	// resolvable — remembering which AID was published without them would leave
	// an address that is remembered and still cannot be reached.
	stored := storedPairingOffer{AID: aid}
	if pub, ok := getPairwiseKey(aid); ok {
		stored.PublicKey = pub
	}
	if kel, ok := getPairwiseKEL(aid); ok {
		stored.KEL = kel
	}
	if serr := savePairingOffer(s.DataDir, stored); serr != nil {
		// Loud, and still served. Refusing to pair because the note could not be
		// written would strand an agent that is otherwise working perfectly; the
		// failure it causes is a restart away, and this is the only warning
		// anybody will get before then.
		log.Printf("[provisioning] WARNING: could not record the pairing identity, so a restart will publish a different one and this address will stop resolving: %v", serr)
	}

	pairingOnce.offer = offer
	writePairingOffer(w, s.withAttestation(pairingOnce.offer))
}

// withAttestation returns the offer with a fresh proof of what this agent is
// running, where the hardware can produce one.
//
// Attached when the offer is SERVED rather than when it is minted, and that is
// not a refactor for its own sake: an offer restored from disk after a restart
// was minted by a process that is gone, so an attestation captured at mint time
// would either be missing or would be a report from a previous boot. A verifier
// asking now should be answered now.
//
// The report is bound to the AID. One that only says "some sealed machine ran
// the right image" is satisfied by any machine anywhere, including the
// provider's own; bound to this AID it says "the machine that minted THIS
// identity ran the right image", which is the claim somebody pairing actually
// needs.
//
// The original is not modified — callers hold a pointer to the remembered offer,
// and a per-request field does not belong in it.
func (s *CoreServer) withAttestation(offer *pairingOffer) *pairingOffer {
	if offer == nil {
		return nil
	}
	out := *offer
	if !secureenclave.SNPAvailable() {
		return &out
	}
	report, rerr := secureenclave.GetSNPReport(out.AID)
	if rerr != nil {
		// Being on sealed hardware and failing to prove it is worth saying out
		// loud: it is the case where the agent is fine but nobody can tell.
		log.Printf("[provisioning] SNP guest present but no report available: %v", rerr)
		return &out
	}
	out.Attestation = base64.StdEncoding.EncodeToString(report.Raw)
	out.AttestationBinding = "blake3-256(IA-SNP-BIND-V1\\n" + out.AID + ")"
	return &out
}

// restorePairingOffer puts back the identity this agent published before it was
// last stopped.
//
// Without this an agent that restarts mints a second pairwise AID and offers
// that instead, so the address somebody was given to come and claim it with
// silently stops resolving. Called from Start, after the endpoint service knows
// the agent's current public URL, because the OOBI is composed from it.
//
// Every failure here is reported and none of them stop the agent. An agent that
// cannot restore its published identity is degraded in a specific, describable
// way; one that refuses to start is unreachable in every way at once.
func (s *CoreServer) restorePairingOffer() {
	// A paired agent has an owner and no longer offers itself, so there is
	// nothing to put back.
	if s.DataStore != nil {
		if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
			return
		}
	}

	stored, found, err := loadPairingOffer(s.DataDir)
	if err != nil {
		log.Printf("[provisioning] WARNING: %v — this agent will publish a NEW pairing identity, and any address already handed out will stop resolving", err)
		return
	}
	if !found {
		return
	}

	// The two registries that make the AID resolvable. Both are in memory, so
	// both are empty after a restart: without them the agent remembers which
	// identity it published and still cannot serve it, which to anybody holding
	// the address looks the same as it being gone.
	if stored.PublicKey != "" {
		registerPairwiseKey(stored.AID, stored.PublicKey)
	}
	if len(stored.KEL) > 0 {
		registerPairwiseKEL(stored.AID, stored.KEL)
	} else {
		log.Printf("[provisioning] WARNING: the recorded pairing identity %s has no key event log, so its OOBI will not resolve", stored.AID)
	}

	// Composed from where this agent is reachable NOW. Storing the address
	// instead of rebuilding it would pin the agent to wherever it happened to be
	// when it first started, which is the same class of bug one layer along.
	oobi := fmt.Sprintf("%s/public/oobi/%s", s.EndpointService.CurrentURL(), stored.AID)
	offer, oerr := newPairingOffer(stored.AID, oobi)
	if oerr != nil {
		log.Printf("[provisioning] WARNING: could not rebuild the published pairing offer: %v", oerr)
		return
	}

	pairingOnce.Lock()
	pairingOnce.offer = offer
	pairingOnce.Unlock()
	log.Printf("[provisioning] still offering the pairing identity published before this start (%s)", stored.AID)
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

// resetPairingOfferForTest lets tests start from a clean slate.
//
// It clears only the in-memory copy, which is what a restart does — the record
// on disk is what makes the offer survive one. A test that wants an agent with
// no history should use a fresh data directory as well.
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
	// A computer offered from its own screen is told who to expect BY WHOEVER
	// SCANNED IT, and the code is what earns the right to say so.
	//
	// This is the same route the provisioning host uses, deliberately. There is
	// one mechanism — a machine is told which identity may claim it, before the
	// claim — and the only thing that differs is who does the telling and how
	// they came by the code. On a machine somebody else set up, the host knows
	// the code because it minted it. On a machine in front of you, the person
	// knows it because it is on the screen.
	//
	// WHAT THIS BUYS is the window. Before it, a displayed code stood for its
	// full ten minutes and any valid claimant could use it. Now the machine
	// locks to the first identity that presents the code, which in practice is
	// seconds after the person scans — so somebody who sees the screen later is
	// refused rather than racing.
	//
	// It cannot make the machine safe from somebody who sees the screen FIRST:
	// they can present the code and prove control of an identity of their own,
	// and first-write-wins means they get it. That is bounded by the code never
	// leaving the screen, and it is why the screen goes on to show WHICH
	// identity took the machine.
	if code, live := localPairingOffer(); live {
		if subtle.ConstantTimeCompare([]byte(code), []byte(body.ClaimToken)) != 1 {
			writeError(w, http.StatusForbidden, "Wrong code",
				"this computer is showing a code on its own screen, and only whoever can "+
					"read it may say who is allowed to claim it")
			return
		}
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
