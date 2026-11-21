package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"identity-agent-core/store"
	"io"
	"net/http"

	"identity-agent-core/internal/jsonreply"
)

// The identity a machine will answer to, minted before the machine exists.
//
// ORDERING IS WHY THIS ROUTE EXISTS. A machine is told who may claim it BEFORE
// it starts — that is what stops whoever reaches it first from taking it. So
// the owner identity has to exist before the machine is asked for, which is
// earlier than adoption, which is where it would otherwise be minted.
//
// It is a pairwise identity like any other: derived from this device's seed at
// an index, meaningful in this one relationship and nowhere else. Somebody who
// intercepts it learns an identifier that says nothing about who its owner is.

type machineOwnerResponse struct {
	// AID is what the provisioning host is told, and what the machine will
	// accept as its owner.
	AID string `json:"aid"`
	// OOBI is where this identity's key log can be fetched from.
	//
	// Handed to the provisioning host alongside the AID so the machine can go
	// and READ the history rather than only being shown it. A presented log is
	// self-verifying but cannot reveal an event withheld from it; fetching, and
	// asking the witnesses named in that log, is what closes that.
	//
	// Sending it discloses nothing the machine will not learn at the claim: it
	// is a pairwise identity, so the address it names says only that some
	// identity is reachable there.
	OOBI string `json:"oobi,omitempty"`
	// Deliberately no index. Where the key comes from is remembered on this
	// device and looked up at adoption; sending it out would put a fact that
	// only matters here into a round trip that could return it wrong.
}

// mintMachineOwnerRequest is the optional body of a mint.
type mintMachineOwnerRequest struct {
	// Kind is what the identity is minted to own: "individual" for a person's
	// own machine, "organisation" for an organisation's Identity Agent. No key
	// log carries it, so it is kept with the identity from the moment it is
	// minted (ADR-087 decision 13). Left out, nothing is recorded: a guess
	// written down would read later as a fact. (An owner identity minted
	// while adopting a machine takes the kind of that claim instead.)
	Kind string `json:"kind"`
}

// The kinds of Identity Agent an owner identity is minted to own.
const (
	machineKindIndividual   = "individual"
	machineKindOrganisation = "organisation"
)

// isAMachineKind says whether kind is one an owner identity is minted for.
func isAMachineKind(kind string) bool {
	return kind == machineKindIndividual || kind == machineKindOrganisation
}

func (s *CoreServer) handleMintMachineOwner(w http.ResponseWriter, r *http.Request) {
	var req mintMachineOwnerRequest
	if r.Body != nil {
		err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req)
		if err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "body must be JSON", err.Error())
			return
		}
	}
	if req.Kind != "" && !isAMachineKind(req.Kind) {
		writeError(w, http.StatusBadRequest, "Unknown kind",
			"an identity is minted to own a computer of your own (individual) or an "+
				"organisation, and "+req.Kind+" is neither")
		return
	}
	aid, oobi, err := s.mintAnIdentityToClaimAMachineWith(req.Kind)
	if err != nil {
		if refuseIfRootSeedRefused(w, err) {
			return
		}
		writeError(w, http.StatusInternalServerError,
			"Could not mint an identity for this machine", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, machineOwnerResponse{AID: aid, OOBI: oobi})
}

// mintAnIdentityToClaimAMachineWith derives, records and publishes an identity
// this device can claim a machine as. kind is what it is minted to own, or
// empty where the caller cannot say.
//
// Separated from the route because it is needed before there is anything to
// route to. A machine is told which identity may claim it BEFORE it starts, so
// the identity has to exist earlier than the moment somebody asks for a machine
// -- and the earliest point this device is in the conversation at all is when
// its owner agrees to own the organisation. Minting it there, rather than at
// claim time, is what stops the two being different identities and the machine
// refusing its own owner.
func (s *CoreServer) mintAnIdentityToClaimAMachineWith(kind string) (aid, oobi string, err error) {
	aid, oobi, _, err = s.mintAMachineOwnerIdentity("machine-owner", kind)
	return aid, oobi, err
}

// mintAMachineOwnerIdentity is the one way an owner identity is minted: a
// pairwise identity in the machines pool, recorded with the index its key
// comes from and what it was minted to own, and with its key log kept.
//
// Every mint passes here because each of the three is needed later and none
// can be recovered: without the index the identity can never sign again,
// without the kind a rebuilt record has to guess it, and without the kept log
// the identity can neither prove itself after a restart nor have its log
// extended.
func (s *CoreServer) mintAMachineOwnerIdentity(name, kind string) (aid, oobi string, idx int, err error) {
	aid, oobi, _, idx, err = s.mintPairwiseIn("machines", name)
	if err != nil {
		return "", "", 0, fmt.Errorf("could not mint an identity for this machine: %w", err)
	}
	// Remembered here rather than handed out and taken back. Adoption looks it
	// up; an index that travelled through a caller would have to be trusted or
	// verified, and neither is needed when this side minted it.
	if err := s.DataStore.RememberMachineOwnerIdentity(aid, idx, kind); err != nil {
		return "", "", 0, fmt.Errorf("could not record the identity for this machine: %w", err)
	}
	// Its key log is written down too, not only held in memory.
	//
	// The machine checks a claim against this log before it will answer to
	// anybody. A machine reserved today and collected tomorrow is claimed after
	// a restart, so a log that lived only in memory would leave the identity
	// unable to prove itself — and the machine correctly refusing its own
	// owner, permanently, with no way back.
	if err := s.persistPairwiseKEL(aid); err != nil {
		return "", "", 0, fmt.Errorf("could not record this identity's key log, without which "+
			"it could not prove itself to the machine later: %w", err)
	}
	return aid, oobi, idx, nil
}

// persistPairwiseKEL writes a freshly minted pairwise identity's key log to
// the store, so it outlives this process.
func (s *CoreServer) persistPairwiseKEL(aid string) error {
	kel, ok := s.getPairwiseKEL(aid)
	if !ok || len(kel) == 0 {
		return fmt.Errorf("no key log was produced for %s", aid)
	}
	for i, ev := range kel {
		body, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		rec := store.EventRecord{
			AID:            aid,
			SequenceNumber: i,
			EventJSON:      string(body),
		}
		if t, _ := ev["t"].(string); t != "" {
			rec.EventType = t
		}
		// The canonical bytes and the signature travel where the engine kept
		// them: the far side checks the event's own digest against those bytes,
		// and checks authorship against that signature. Without either it can
		// tell the log is well formed and nothing more.
		if raw, _ := ev["raw_bytes_b64"].(string); raw != "" {
			rec.RawBytesB64 = raw
		}
		if sig, _ := ev["cesr_signature"].(string); sig != "" {
			rec.CesrSignature = sig
		}
		if k, _ := ev["public_key"].(string); k != "" {
			rec.PublicKey = k
		}
		if err := s.DataStore.SaveEvent(rec); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
	}
	return nil
}
