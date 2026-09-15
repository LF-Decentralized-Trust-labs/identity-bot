package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Remembering the identity this agent enrolled with a relay operator.
//
// A relay allocation is a durable address: the whole reason to prefer it over a
// tunnel is that it is provably this agent's and can be handed to a counterparty
// who has to find the agent again months later. That promise only holds if the
// SAME enrollment AID is presented on every start — the operator maps the AID to
// an allocation, so a fresh AID each start means a fresh allocation and a new
// public URL, silently breaking every address already handed out.
//
// The enrollment used to be minted fresh on every start and kept only in memory,
// so each restart re-enrolled and the relay's public URL changed — defeating the
// point of a relay. This records which enrollment was minted so the next start
// reuses it instead of minting another.
//
// It is a file next to the root seed rather than a row in the data store, for the
// same reason the pairing offer is: it is a fact this agent must know about
// itself early in startup, and it mirrors that established pattern exactly.
//
// The signing seed is deliberately NOT stored. It is re-derived from the root
// seed and RelationshipIndex on demand — the same rule login follows for its
// per-site relationship keys — so the only secret on disk stays the root seed.

const relayEnrollmentFileName = "relay-enrollment.json"

// storedRelayEnrollment is what has to survive a restart for a relay's public
// URL to stay stable across restarts.
//
// The OOBI is deliberately NOT stored. It is composed from the agent's current
// public URL, which legitimately changes, so storing it would pin the agent to
// wherever it was when it first enrolled — the same class of bug this whole
// record exists to prevent, one layer along. The AID is the durable fact; the
// address is looked up fresh.
type storedRelayEnrollment struct {
	// BaseURL is the operator this enrollment belongs to. A different operator is
	// a different enrollment, so an enrollment recorded for one operator is not
	// reused for another — that would present one operator's AID to another.
	BaseURL string `json:"base_url"`
	// AID is the pairwise enrollment identity. It is a digest of an inception
	// event, so it cannot be re-derived from the index alone and must be stored.
	AID string `json:"aid"`
	// RelationshipIndex is the HD index the enrollment seed derives from. It is
	// the only way back to the signing key; without it the enrollment can never
	// sign again. The seed itself is never stored — it is re-derived from the
	// root seed and this index on demand.
	RelationshipIndex int `json:"relationship_index"`
	// PublicKey is the base64url Ed25519 verification key, which is what
	// /public/{aid}/did.json serves.
	PublicKey string `json:"public_key"`
	// KEL is the key event log, which is what /public/oobi/{aid} serves. Without
	// it the AID is remembered but cannot be resolved, which to the operator is
	// indistinguishable from it being gone.
	KEL []map[string]interface{} `json:"kel"`
}

func relayEnrollmentPath(dataDir string) string {
	return filepath.Join(dataDir, relayEnrollmentFileName)
}

// saveRelayEnrollment records the enrollment this agent has just minted.
//
// Written with the same atomic write-flush-rename-flush dance as the pairing
// offer, and for the same reason: this record is written by an agent that is
// often killed rather than shut down, and a write-and-rename that never reaches
// the disk leaves a restart re-enrolling and the public URL moving — the exact
// failure this closes.
func saveRelayEnrollment(dataDir string, enr storedRelayEnrollment) error {
	if dataDir == "" {
		return fmt.Errorf("no data directory, so the relay enrollment cannot be remembered")
	}
	if enr.AID == "" {
		return fmt.Errorf("refusing to record a relay enrollment with no AID")
	}
	if enr.BaseURL == "" {
		return fmt.Errorf("refusing to record a relay enrollment with no operator")
	}
	raw, err := json.MarshalIndent(enr, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	tmp := relayEnrollmentPath(dataDir) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("the relay enrollment could not be flushed to disk, so it would not survive this agent stopping: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, relayEnrollmentPath(dataDir)); err != nil {
		os.Remove(tmp)
		return err
	}
	if dir, derr := os.Open(dataDir); derr == nil {
		if serr := dir.Sync(); serr != nil {
			log.Printf("[relay] WARNING: could not flush the directory holding the relay enrollment, "+
				"so it may not survive this agent stopping: %v", serr)
		}
		dir.Close()
	}
	return nil
}

// loadRelayEnrollment reads back the enrollment this agent minted, if any.
//
// A missing file is not an error: an agent that has never enrolled with a relay
// is the ordinary case.
func loadRelayEnrollment(dataDir string) (*storedRelayEnrollment, bool, error) {
	if dataDir == "" {
		return nil, false, nil
	}
	raw, err := os.ReadFile(relayEnrollmentPath(dataDir))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var enr storedRelayEnrollment
	if err := json.Unmarshal(raw, &enr); err != nil {
		return nil, false, fmt.Errorf(
			"the recorded relay enrollment is unreadable, so this agent cannot tell which enrollment it presented: %w", err)
	}
	if enr.AID == "" {
		return nil, false, fmt.Errorf("the recorded relay enrollment has no AID")
	}
	return &enr, true, nil
}
