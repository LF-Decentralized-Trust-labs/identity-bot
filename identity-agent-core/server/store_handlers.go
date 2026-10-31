package server

// store_handlers.go — pure DataStore endpoints that do NOT require the Python KERI driver.
// Mobile Go Core uses these to persist receipts and credentials it produced itself.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// handleStoreReceipt accepts a pre-validated witness receipt and persists it.
//
// POST /api/store/receipt
//
//	{
//	  "event_said":      "<44-char SAID>",
//	  "witness_aid":    "<AID>",
//	  "cesr_signature": "0B..."
//	}
func (s *CoreServer) handleStoreReceipt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EventSAID     string `json:"event_said"`
		WitnessAID    string `json:"witness_aid"`
		CesrSignature string `json:"cesr_signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.EventSAID == "" || req.WitnessAID == "" || req.CesrSignature == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "event_said, witness_aid, cesr_signature are required")
		return
	}

	record := store.WitnessReceiptRecord{
		EventSAID:     req.EventSAID,
		WitnessAID:    req.WitnessAID,
		CesrSignature: req.CesrSignature,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.DataStore.SaveWitnessReceipt(record); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrReceiptDoesNotVerify) {
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, "Failed to store receipt", err.Error())
		return
	}

	log.Printf("[identity-agent-core] STORE: Receipt saved for event %s from witness %s", req.EventSAID, req.WitnessAID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "saved"})
}

// handleGetStoreReceipts retrieves all stored witness receipts for an event SAID.
//
// GET /api/store/receipts?event_said=<SAID>&threshold=<int>
//
// receipt_count and threshold_met are judged as receiptsAgainstItsLog says:
// designated witnesses only, once each, against at least the event's own
// threshold. Every stored receipt is still listed.
func (s *CoreServer) handleGetStoreReceipts(w http.ResponseWriter, r *http.Request) {
	eventSAID := r.URL.Query().Get("event_said")
	if eventSAID == "" {
		writeError(w, http.StatusBadRequest, "Missing event_said query parameter", "")
		return
	}
	threshold := 0
	if t := r.URL.Query().Get("threshold"); t != "" {
		fmt.Sscanf(t, "%d", &threshold)
	}

	receipts, err := s.DataStore.GetWitnessReceipts(eventSAID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read receipts", err.Error())
		return
	}

	counted, thresholdMet := s.receiptsAgainstItsLog(eventSAID, receipts, threshold)

	type entry struct {
		WitnessAID    string `json:"witness_aid"`
		CesrSignature string `json:"cesr_signature"`
		ReceivedAt    string `json:"received_at"`
	}
	entries := make([]entry, 0, len(receipts))
	for _, rec := range receipts {
		entries = append(entries, entry{
			WitnessAID:    rec.WitnessAID,
			CesrSignature: rec.CesrSignature,
			ReceivedAt:    rec.ReceivedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"event_said":    eventSAID,
		"receipts":      entries,
		"receipt_count": counted,
		"threshold_met": thresholdMet,
	})
}

// handleStoreCredential persists an ACDC credential record without requiring the KERI driver.
//
// POST /api/store/credential
//
//	{
//	  "said":           "<ACDC SAID>",
//	  "issuer_aid":     "<AID>",
//	  "holder_aid":     "<AID>",
//	  "schema_said":    "<SAID>",
//	  "acdc_json_b64":  "<base64>",
//	  "ixn_said":       "<SAID>",
//	  "cesr_signature": "0B...",
//	  "status":         "issued"
//	}
func (s *CoreServer) handleStoreCredential(w http.ResponseWriter, r *http.Request) {
	var req store.CredentialRecord
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.SAID == "" || req.IssuerAID == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "said and issuer_aid are required")
		return
	}
	if req.IssuedAt == "" {
		req.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if req.Status == "" {
		req.Status = "issued"
	}

	if err := s.DataStore.SaveCredential(req); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to store credential", err.Error())
		return
	}

	log.Printf("[identity-agent-core] STORE: Credential saved - SAID: %s issuer: %s", req.SAID, req.IssuerAID)
	s.notifyBackupEvent(backup.EventCredential)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "saved", "said": req.SAID})
}

// receiptsAgainstItsLog counts the designated witnesses of eventSAID, in the
// key log of the identity it belongs to (logOfEvent), whose receipt among
// receipts verifies, each once by its key, and reports whether that meets
// the threshold.
//
// The witnesses and the threshold come from the event, never from the caller.
// A caller's threshold is honoured only when it asks for more than the event
// does: a lower one would let a caller declare an event witnessed that its
// own witnesses have not, and a receipt from a witness the event never named
// is no vote however well it verifies. An event in no key log kept here has
// no designated witnesses, so nothing counts.
func (s *CoreServer) receiptsAgainstItsLog(eventSAID string, receipts []store.WitnessReceiptRecord, callerThreshold int) (counted int, met bool) {
	in, found := s.logOfEvent(eventSAID)
	if !found {
		return 0, false
	}
	in.Receipts = map[string][]drivers.WitnessReceipt{}
	for _, r := range receipts {
		in.Receipts[eventSAID] = append(in.Receipts[eventSAID],
			drivers.WitnessReceipt{WitnessAID: r.WitnessAID, CesrSignature: r.CesrSignature})
	}
	row, found := drivers.WitnessingOf(in, eventSAID)
	if !found {
		return 0, false
	}
	// row.Met is false wherever the log cannot say who the witnesses are; a
	// caller's threshold can only add to what is required.
	return row.Verified, row.Met && row.Verified >= callerThreshold
}
