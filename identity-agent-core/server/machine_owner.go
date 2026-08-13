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
	// Deliberately no index. Where the key comes from is remembered on this
	// device and looked up at adoption; sending it out would put a fact that
	// only matters here into a round trip that could return it wrong.
}

func (s *CoreServer) handleMintMachineOwner(w http.ResponseWriter, r *http.Request) {
	aid, _, _, idx, err := s.mintPairwiseIn("machines", "machine-owner")
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Could not mint an identity for this machine", err.Error())
		return
	}
	// Remembered here rather than handed out and taken back. Adoption looks it
	// up; an index that travelled through a caller would have to be trusted or
	// verified, and neither is needed when this side minted it.
	if err := s.DataStore.RememberMachineOwnerIdentity(aid, idx); err != nil {
		writeError(w, http.StatusInternalServerError,
			"Could not record the identity for this machine", err.Error())
		return
	}
	// Its key log is written down too, not only held in memory.
	//
	// The machine checks a claim against this log before it will answer to
	// anybody. A machine reserved today and collected tomorrow is claimed after
	// a restart, so a log that lived only in memory would leave the identity
	// unable to prove itself — and the machine correctly refusing its own
	// owner, permanently, with no way back.
	if err := s.persistPairwiseKEL(aid); err != nil {
		writeError(w, http.StatusInternalServerError,
			"Could not record this identity's key log",
			"without it this identity could not prove itself to the machine later: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(machineOwnerResponse{AID: aid})
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
