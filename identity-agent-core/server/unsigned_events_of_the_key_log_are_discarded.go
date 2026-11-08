package server

// Events an earlier version wrote into the key log without the identity's key.
//
// An Identity Agent upgraded from a version that wrote them, where the
// identity's key is now on another device, holds interactions that device never
// had and never signed: approvals of delegated identities, and grants, stored
// unsigned. A key log with an unsigned event in it verifies for nobody, and
// the device cannot extend a log it does not hold, so nothing more can be asked
// of it (errUnsignedKeyLog).
//
// They are discarded, not signed. The device would be signing bytes it never
// saw, anchoring things the owner was never shown, and the key never authorised
// them: rewinding the log here to what the device holds is the one answer that
// makes no claim the key did not. Discarded is set aside, never deleted
// (store.SetAsideEventsFrom), and what the events had anchored is undone with
// them: a grant they issued is no longer in force, and an identity delegated
// by an approval among them waits for its approval afresh, and is asked of the
// device as a new one is (a_delegation_waits_for_the_device_that_holds_the_key.go).

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// credentialStatusDiscarded is a grant whose anchoring event was discarded
// from the key log: never in force, and nothing to withdraw, since the key log
// no longer names it.
const credentialStatusDiscarded = "discarded"

// discardedUnsignedEvents says what discarding the unsigned events did.
type discardedUnsignedEvents struct {
	Discarded []int `json:"discarded"`
	// GrantsNotInForce are grants the discarded events anchored.
	GrantsNotInForce []string `json:"grants_not_in_force,omitempty"`
	// AgentsAskedAgain are delegated identities whose approval was among
	// them, now waiting for the device that holds the key to approve them.
	AgentsAskedAgain []string `json:"assets_asked_again,omitempty"`
	// Unasked are those that could not be asked, and why.
	Unasked map[string]string `json:"assets_not_asked,omitempty"`
	// RegistriesNotAnchored are registries whose inception the discarded
	// events anchored. They are named, not removed: what issues into them is
	// not asked for until they are made again.
	RegistriesNotAnchored []string `json:"registries_not_anchored,omitempty"`
}

// discardUnsignedOwnEvents rewinds the key log here to what the device that
// holds the key has: everything before the first event carrying no signature.
func (s *CoreServer) discardUnsignedOwnEvents() (*discardedUnsignedEvents, error) {
	adoptMu.Lock()
	defer adoptMu.Unlock()
	if s.DataStore == nil || !s.keyIsElsewhere() {
		return nil, errors.New("the key of this identity is held here, which signs what it writes; nothing is written to its key log unsigned")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return nil, errors.New("no identity")
	}
	events, err := s.DataStore.GetEvents(identity.AID)
	if err != nil {
		return nil, err
	}
	from := -1
	for i, ev := range events {
		if ev.CesrSignature == "" && ev.SequenceNumber > 0 {
			from = i
			break
		}
	}
	out := &discardedUnsignedEvents{Discarded: []int{}}
	if from < 0 {
		return out, nil
	}
	// Only a tail of unsigned interactions is rewound: a signed event after an
	// unsigned one, or an unsigned rotation, is not what an earlier version
	// wrote and cannot be undone by forgetting the events after it.
	said := map[string]bool{}
	var seals []map[string]interface{}
	for _, ev := range events[from:] {
		if ev.CesrSignature != "" || ev.EventType != "ixn" {
			return nil, fmt.Errorf("event %d of the key log is %s and %s, which is not the unsigned interactions an earlier version wrote; "+
				"it is not discarded", ev.SequenceNumber, ev.EventType, map[bool]string{true: "unsigned", false: "signed"}[ev.CesrSignature == ""])
		}
		var body struct {
			D string                   `json:"d"`
			A []map[string]interface{} `json:"a"`
		}
		if json.Unmarshal([]byte(ev.EventJSON), &body) != nil {
			return nil, fmt.Errorf("event %d of the key log is unreadable", ev.SequenceNumber)
		}
		said[body.D] = true
		seals = append(seals, body.A...)
		out.Discarded = append(out.Discarded, ev.SequenceNumber)
	}
	if err := s.DataStore.SetAsideEventsFrom(identity.AID, events[from].SequenceNumber); err != nil {
		return nil, fmt.Errorf("the events could not be set aside: %w", err)
	}
	// The engine holds the log in memory: it is read again from what is left.
	s.reloadIdentityIntoDriver()
	log.Printf("[grants] %d unsigned event(s) of %s, written by an earlier version without its key, were set aside (places %v)",
		len(out.Discarded), identity.AID, out.Discarded)

	if creds, err := s.DataStore.GetCredentials(); err == nil {
		for _, c := range creds {
			if c.IssuerAID == identity.AID && said[c.IxnSAID] && c.Status != "revoked" && c.Status != credentialStatusDiscarded {
				if err := s.DataStore.UpdateCredentialStatus(c.SAID, credentialStatusDiscarded); err == nil {
					out.GrantsNotInForce = append(out.GrantsNotInForce, c.SAID)
				}
			}
		}
	}
	if reg, err := s.DataStore.GetRegistryByIssuer(identity.AID); err == nil && reg != nil {
		if anchoredBy(seals, reg.RegistrySAID) {
			out.RegistriesNotAnchored = append(out.RegistriesNotAnchored, reg.RegistrySAID)
		}
	}
	s.askForDiscardedApprovals(identity.AID, seals, out)
	return out, nil
}

func anchoredBy(seals []map[string]interface{}, subject string) bool {
	for _, seal := range seals {
		if seal["i"] == subject && seal["s"] == "0" {
			return true
		}
	}
	return false
}

// askForDiscardedApprovals sends back to the device that holds the key every
// delegated identity whose approval was among the discarded events.
func (s *CoreServer) askForDiscardedApprovals(delegator string, seals []map[string]interface{}, out *discardedUnsignedEvents) {
	if s.assetHandler == nil {
		return
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		out.Unasked = map[string]string{"": err.Error()}
		return
	}
	for _, a := range assets {
		if a.DelegatorAID != delegator || a.ApprovalPending || !anchoredBy(seals, a.PairwiseAID) {
			continue
		}
		a.ApprovalPending, a.UpdatedAt = true, time.Now().UTC()
		if err := s.assetHandler.Store.UpsertAsset(a); err != nil {
			s.noteUnasked(out, a.ID, err)
			continue
		}
		if err := s.askApprovalAgain(a.ID); err != nil {
			s.noteUnasked(out, a.ID, err)
			continue
		}
		out.AgentsAskedAgain = append(out.AgentsAskedAgain, a.ID)
	}
}

func (s *CoreServer) noteUnasked(out *discardedUnsignedEvents, id string, err error) {
	if out.Unasked == nil {
		out.Unasked = map[string]string{}
	}
	out.Unasked[id] = err.Error()
}

// handleDiscardUnsignedEvents is the owner choosing to discard the events
// keyLogReport names as key_log_unsigned_events.
func (s *CoreServer) handleDiscardUnsignedEvents(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "only this agent's owner rewinds its key log")
		return
	}
	res, err := s.discardUnsignedOwnEvents()
	if err != nil {
		writeError(w, http.StatusConflict, "not discarded", err.Error())
		return
	}
	writeJSON(w, res)
}
