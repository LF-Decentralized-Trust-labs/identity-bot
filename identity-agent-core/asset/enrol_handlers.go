package asset

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/secureenclave"

	"github.com/go-chi/chi/v5"
)

// HandleCreateEnrolment issues a token for one machine. Owner only.
func (h *Handler) HandleCreateEnrolment(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisplayName string `json:"display_name"`
		AssetType   string `json:"asset_type"`
		Origin      string `json:"origin"`
		ExpiresInS  int    `json:"expires_in_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeJSON(w, map[string]string{"error": "bad request"}, http.StatusBadRequest)
		return
	}

	e := Enrolment{
		DisplayName: strings.TrimSpace(body.DisplayName),
		AssetType:   strings.TrimSpace(body.AssetType),
		Origin:      strings.TrimSpace(body.Origin),
	}
	if body.ExpiresInS > 0 {
		e.ExpiresAt = time.Now().UTC().Add(time.Duration(body.ExpiresInS) * time.Second)
	}

	created, err := h.Store.CreateEnrolment(e)
	if err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}
	h.writeJSON(w, created, http.StatusCreated)
}

func (h *Handler) HandleListEnrolments(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, h.Store.ListEnrolments(), http.StatusOK)
}

func (h *Handler) HandleRevokeEnrolment(w http.ResponseWriter, r *http.Request) {
	if err := h.Store.RevokeEnrolment(chi.URLParam(r, "token")); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusNotFound)
		return
	}
	h.writeJSON(w, map[string]string{"status": "revoked"}, http.StatusOK)
}

// HandleEnrol is the machine's side: it presents the key it generated and the
// token it was given, and receives a delegated identity over that key.
//
// Reachable without being the owner, because the machine enrolling is not the
// owner and never will be. The token is what authorises it, and it is
// single-use, time-bounded, and describes in advance what it may enrol.
func (h *Handler) HandleEnrol(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token         string `json:"token"`
		PublicKey     string `json:"public_key"`
		NextPublicKey string `json:"next_public_key"`
		// Signature over EnrolProofPayload, made with the private half of
		// PublicKey. Without it the token alone decides what gets enrolled.
		Signature string `json:"signature"`
		// AttestationReport is an optional base64 SEV-SNP report from the
		// machine, bound to the key it is enrolling. Optional because most
		// machines cannot produce one, and refusing those would mean no machine
		// could enrol until every one of them had the hardware.
		AttestationReport string `json:"attestation_report,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeJSON(w, map[string]string{"error": "bad request"}, http.StatusBadRequest)
		return
	}
	if body.Token == "" || body.PublicKey == "" || body.NextPublicKey == "" {
		h.writeJSON(w, map[string]string{
			"error": "token, public_key and next_public_key are all required",
		}, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	// Claim before minting. Checking the token and then spending it after a
	// round trip to the KERI engine leaves a window in which two machines both
	// pass the check and both get an identity anchored in the owner's KEL — and
	// an anchored identity cannot be taken back, while a wrongly-spent token
	// can be reissued.
	enrolment, err := h.Store.ClaimEnrolment(body.Token, now)
	if err != nil {
		// Deliberately vague, and the same answer for every reason. Telling
		// somebody guessing that a token exists but is spent tells them which
		// guesses were close.
		h.writeJSON(w, map[string]string{"error": "this enrolment token cannot be used"}, http.StatusForbidden)
		return
	}
	// From here on, any exit that has not created an identity must hand the
	// token back, or a machine that failed for a transient reason is locked out
	// of the enrolment it was legitimately issued.
	release := func() {
		if rerr := h.Store.ReleaseEnrolment(body.Token); rerr != nil {
			log.Printf("[asset] enrolment %s could not be released: %v", body.Token, rerr)
		}
	}

	// Prove the sender holds the key it is asking us to delegate over. A token
	// says who was authorised to enrol A machine; this says which machine.
	if err := verifyEnrolProof(body.Token, body.PublicKey, body.NextPublicKey, body.Signature); err != nil {
		release()
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusForbidden)
		return
	}

	// Identify the hardware, if it can be identified at all.
	//
	// Recorded rather than required. Attestation cannot prove a machine is ours
	// — the manufacturer's key service answers to anyone — so this value is only
	// worth anything alongside the human moment that says "this one". What it
	// gives us is the ability to notice later that the machine changed.
	//
	// A machine with no attestation still enrols, and the record says so. The
	// alternative is that nothing can enrol until every machine has the
	// hardware, and the temptation then is to fake a pass — which is how a
	// system ends up asserting a property it does not have.
	machine, machineWhy := h.identifyEnrollingMachine(body.AttestationReport, body.PublicKey)

	// A delegated identity or nothing. The whole point of enrolling a machine
	// this way is that its authority comes from, and ends with, its owner.
	rootAID := ""
	if h.RootAID != nil {
		rootAID = h.RootAID()
	}
	if rootAID == "" {
		release()
		h.writeJSON(w, map[string]string{
			"error": "this agent has no identity yet, so it has nothing to delegate from",
		}, http.StatusConflict)
		return
	}
	if h.KeriDriver == nil {
		release()
		h.writeJSON(w, map[string]string{"error": "no KERI engine"}, http.StatusServiceUnavailable)
		return
	}

	// Delegate over the key the MACHINE generated. Nothing here derives a key,
	// which is the difference between this and every other asset: the private
	// half stays where it was made and never reaches this agent.
	resp, err := h.KeriDriver.CreateDelegatedInception(
		body.PublicKey, body.NextPublicKey, enrolment.DisplayName, rootAID)
	if err != nil {
		release()
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
		return
	}
	// The delegation is only real once our own KEL records it. Persisting the
	// anchor first means a failure here leaves no asset claiming an identity
	// nobody can verify.
	if err := h.persistDelegationAnchor(rootAID, resp.DelegatorIxn); err != nil {
		release()
		h.writeJSON(w, map[string]string{
			"error": "the delegation could not be anchored, so it was not issued: " + err.Error(),
		}, http.StatusInternalServerError)
		return
	}

	a := Asset{
		ID:          genID(),
		DisplayName: enrolment.DisplayName,
		AssetType:   enrolment.AssetType,
		// Taken from the token, not from the request. A machine does not get to
		// tell the owner where it lives.
		Origin:      enrolment.Origin,
		PairwiseAID: resp.AID,
		// Recorded so this machine's later requests can be verified. Without it
		// the enrolment produces an identity nothing can check a signature
		// against, which is most of the point of having enrolled.
		PublicKey:       body.PublicKey,
		DelegationModel: "delegated",
		DelegatorAID:    resp.DelegatorAID,
		// Which physical machine this was, at the one moment somebody could
		// vouch for it in person. Every later attestation is checked against
		// this; without it, a report from any machine of the same make passes.
		MachineIDKind:  string(machine.Kind),
		MachineIDValue: machine.Value,
		MachineIDWhy:   machineWhy,
		// No SigningIndex. That field records where an asset's key sits in the
		// owner's derivation tree, and this asset's key is not in it at all.
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.Store.UpsertAsset(a); err != nil {
		release()
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
		return
	}
	// The token was claimed before any of this; record what it produced. A
	// failure here has already created the identity, so releasing would be
	// wrong — it would authorise a second one.
	if err := h.Store.RecordEnrolmentAsset(body.Token, a.ID); err != nil {
		log.Printf("[asset] enrolment %s produced asset %s but the link was not recorded: %v",
			body.Token, a.ID, err)
	}

	out := map[string]interface{}{
		"asset":         a,
		"aid":           resp.AID,
		"delegator_aid": resp.DelegatorAID,
		// The machine needs its own inception event to serve its KEL and be
		// verifiable by anyone else.
		"dip_event": resp.DipEvent,
		"machine":   machine,
	}
	if !machine.Known() {
		// Say it in the response, not only in the record. An operator enrolling
		// a machine they believe is attested should find out now, not when
		// something later declines to trust it.
		out["machine_warning"] = "this machine enrolled without a hardware identity, so a " +
			"later attestation cannot be checked against the machine that enrolled: " + machineWhy
	}
	h.writeJSON(w, out, http.StatusCreated)
}

// identifyEnrollingMachine derives the hardware identity of the machine on the
// other end, or explains why it could not.
//
// The attestation report is bound to the key being enrolled, and that binding
// is checked here: an unbound report proves only that SOME sealed machine
// exists somewhere, which is satisfied by the attacker's own and says nothing
// about the machine sending this request.
func (h *Handler) identifyEnrollingMachine(reportB64, publicKey string) (secureenclave.MachineIdentity, string) {
	if strings.TrimSpace(reportB64) == "" {
		return secureenclave.MachineIdentity{}, "the machine sent no attestation report"
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(reportB64))
	if err != nil {
		return secureenclave.MachineIdentity{}, "the attestation report was not valid base64"
	}
	parsed, err := secureenclave.ParseSNPReport(raw)
	if err != nil {
		return secureenclave.MachineIdentity{}, "the attestation report could not be read: " + err.Error()
	}
	// The report must be bound to the key being enrolled. Otherwise a report
	// captured from any sealed machine — including one the attacker runs —
	// would travel with any key at all.
	want := secureenclave.BindReportData(publicKey)
	if !bytes.Equal(parsed.ReportData, want) {
		return secureenclave.MachineIdentity{}, "the attestation report is not bound to the key " +
			"being enrolled, so it does not describe the machine sending this request"
	}
	// A guest the host may read into is not sealed in any sense that matters,
	// however well-formed its report.
	if parsed.DebugAllowed() {
		return secureenclave.MachineIdentity{}, "the attestation report says debug access is " +
			"permitted, so the host can read this machine's memory"
	}
	return secureenclave.MachineIdentity{
		Kind:  secureenclave.MachineIDSNPChip,
		Value: parsed.ChipIDHex(),
	}, ""
}
