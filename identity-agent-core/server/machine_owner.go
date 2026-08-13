package server

import (
	"encoding/json"
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(machineOwnerResponse{AID: aid})
}
