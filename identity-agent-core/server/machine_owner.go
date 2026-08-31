package server

import (
	"encoding/json"
	"fmt"
	"identity-agent-core/store"
	"net/http"
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

func (s *CoreServer) handleMintMachineOwner(w http.ResponseWriter, r *http.Request) {
	aid, oobi, err := s.mintAnIdentityToClaimAMachineWith()
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Could not mint an identity for this machine", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(machineOwnerResponse{AID: aid, OOBI: oobi})
}

// mintAnIdentityToClaimAMachineWith derives, records and publishes an identity
// this device can claim a machine as.
//
// Separated from the route because it is needed before there is anything to
// route to. A machine is told which identity may claim it BEFORE it starts, so
// the identity has to exist earlier than the moment somebody asks for a machine
// -- and the earliest point this device is in the conversation at all is when
// its owner agrees to own the organisation. Minting it there, rather than at
// claim time, is what stops the two being different identities and the machine
// refusing its own owner.
func (s *CoreServer) mintAnIdentityToClaimAMachineWith() (aid, oobi string, err error) {
	aid, oobi, _, idx, err := s.mintPairwiseIn("machines", "machine-owner")
	if err != nil {
		return "", "", fmt.Errorf("could not mint an identity for this machine: %w", err)
	}
	// Remembered here rather than handed out and taken back. Adoption looks it
	// up; an index that travelled through a caller would have to be trusted or
	// verified, and neither is needed when this side minted it.
	if err := s.DataStore.RememberMachineOwnerIdentity(aid, idx); err != nil {
		return "", "", fmt.Errorf("could not record the identity for this machine: %w", err)
	}
	// Its key log is written down too, not only held in memory.
	//
	// The machine checks a claim against this log before it will answer to
	// anybody. A machine reserved today and collected tomorrow is claimed after
	// a restart, so a log that lived only in memory would leave the identity
	// unable to prove itself — and the machine correctly refusing its own
	// owner, permanently, with no way back.
	if err := s.persistPairwiseKEL(aid); err != nil {
		return "", "", fmt.Errorf("could not record this identity's key log, without which "+
			"it could not prove itself to the machine later: %w", err)
	}
	return aid, oobi, nil
}

// persistPairwiseKEL writes a freshly minted pairwise identity's key log to
// the store, so it outlives this process.
func (s *CoreServer) persistPairwiseKEL(aid string) error {
	kel, ok := getPairwiseKEL(aid)
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
