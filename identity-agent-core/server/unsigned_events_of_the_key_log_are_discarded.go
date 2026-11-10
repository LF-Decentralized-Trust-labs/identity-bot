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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
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
//
// Only where no witness can have seen any of them. An earlier version sent its
// unsigned events to witnesses (ADR-061), and an interaction may not supersede
// an event: a fresh event at a place a witness already holds reads as
// duplicity to whoever first saw the discarded one. So nothing is discarded
// unless no receipt is held for any of them and every witness the identity
// names says, with its own signature, that it holds the log only below the
// first. Otherwise the owner is pointed to signing them in place, which is
// the migration for events that may be at witnesses (errDiscardWouldFork).
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
	// No send of the key log to its witnesses is in flight from here to the
	// set-aside: one that had read these events could reach a witness after it
	// was asked what it holds, and the discard would then fork the log.
	s.witnessing.sendMu.Lock()
	defer s.witnessing.sendMu.Unlock()
	if err := s.nothingDiscardedIsAtWitnesses(identity.AID, events[from:]); err != nil {
		return nil, err
	}
	if err := s.DataStore.SetAsideEventsFrom(identity.AID, events[from].SequenceNumber); err != nil {
		return nil, fmt.Errorf("the events could not be set aside: %w", err)
	}
	// The engine holds the log in memory: it is read again from what is left.
	reloadErr := s.reloadIdentityIntoDriver()
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
	s.unmakeDiscardedRegistries(identity.AID, seals, out)
	s.askForDiscardedApprovals(identity.AID, seals, out, reloadErr == nil)
	if reloadErr != nil {
		return nil, fmt.Errorf("%w: %v", errEngineNotReloaded, reloadErr)
	}
	return out, nil
}

// errEngineNotReloaded is events set aside whose rewound log the engine could
// not be handed: they are out of the stored key log and grants and approvals
// are undone, but the engine still holds the old log in memory until it is
// restarted or reloaded, and nothing is asked of the device that holds the key.
var errEngineNotReloaded = errors.New("the events were set aside, but the engine could not be given the rewound key log, so nothing was asked of the device that holds the key; restart this Identity Agent, then ask for each delegated identity's approval again (POST /api/assets/{id}/approval)")

// errDiscardWouldFork is a discard refused because a witness may hold what
// would be discarded.
var errDiscardWouldFork = errors.New("not discarded")

// nothingDiscardedIsAtWitnesses is the condition for discarding: no receipt
// is held for any event to be discarded, and every witness the identity names
// has answered, signed by itself, that its tip is below the first of them.
// A witness that does not answer is not one that holds nothing, so silence
// refuses. The refusal says what can be done instead: an event marked at the
// upgrade is signed in place (POST /api/events/signature); one added unsigned
// after the upgrade is not accepted there, so it is superseded by a recovery
// rotation made on the device that holds the key.
func (s *CoreServer) nothingDiscardedIsAtWitnesses(aid string, tail []store.EventRecord) error {
	marked := false
	for _, ev := range tail {
		if ev.UnsignedAtUpgrade {
			marked = true
		}
	}
	refuse := func(why string) error {
		instead := "they are superseded instead by a recovery rotation made on the device that holds the key"
		if marked {
			instead = "they are signed in place instead, POST /api/events/signature"
		}
		return fmt.Errorf("%w: %s; events that may be at witnesses are not discarded, because a different event at the same place would read as duplicity "+
			"(%s)", errDiscardWouldFork, why, instead)
	}
	for _, ev := range tail {
		// An event marked as unsigned at the upgrade is one ADR-061 says may be
		// at witnesses: it is signed in place and never discarded, whatever the
		// receipts held here and the witnesses asked say.
		if ev.UnsignedAtUpgrade {
			return refuse(fmt.Sprintf("event %d was already in the log, unsigned, when this version took it over, and may be at witnesses", ev.SequenceNumber))
		}
		var body struct {
			D string `json:"d"`
		}
		if json.Unmarshal([]byte(ev.EventJSON), &body) != nil || body.D == "" {
			return refuse(fmt.Sprintf("event %d is unreadable", ev.SequenceNumber))
		}
		receipts, err := s.DataStore.GetWitnessReceipts(body.D)
		if err != nil {
			return refuse(fmt.Sprintf("the receipts held for event %d could not be read: %v", ev.SequenceNumber, err))
		}
		if len(receipts) > 0 {
			return refuse(fmt.Sprintf("a witness has receipted event %d", ev.SequenceNumber))
		}
	}
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok {
		return refuse("the witnesses this identity names cannot be read from the engine")
	}
	witnesses, _, err := keeper.WitnessConfig(aid)
	if err != nil {
		return refuse(fmt.Sprintf("the witnesses this identity names could not be read: %v", err))
	}
	if len(witnesses) == 0 {
		return nil
	}
	if s.WitnessService == nil {
		return refuse("witnesses are named and cannot be asked from here")
	}
	first := tail[0].SequenceNumber
	ctx, cancel := context.WithTimeout(context.Background(), witnessAskTimeout)
	defer cancel()
	held, silent := s.WitnessService.KelHeldByEach(ctx, aid, witnesses)
	if len(silent) > 0 {
		return refuse(fmt.Sprintf("witness %s did not say what it holds", silent[0]))
	}
	for key, tip := range held {
		if tip.SN >= first {
			return refuse(fmt.Sprintf("witness %s holds this identity's log up to event %d", key, tip.SN))
		}
	}
	return nil
}

// unmakeDiscardedRegistries makes unusable every registry whose inception the
// discarded events anchored: nothing in the key log names it any more, so
// nothing issued into it could be proved. Its stored inception is cleared,
// which is how a registry that cannot be used is already told apart
// (ensureRegistry, issueAssetCredential), so the next grant makes a registry
// again and anchors it in the log as it now is. It is named, not deleted.
func (s *CoreServer) unmakeDiscardedRegistries(issuer string, seals []map[string]interface{}, out *discardedUnsignedEvents) {
	regs, err := s.DataStore.ListRegistries()
	if err != nil {
		log.Printf("[grants] the registries could not be read to find those the discarded events anchored: %v", err)
		return
	}
	for _, reg := range regs {
		if reg.IssuerAID != issuer || reg.VcpRawB64 == "" || !anchoredBy(seals, reg.RegistrySAID) {
			continue
		}
		if err := s.DataStore.ForgetRegistryInception(reg.RegistrySAID); err != nil {
			log.Printf("[grants] registry %s was anchored by a discarded event and could not be made unusable: %v", reg.RegistrySAID, err)
			continue
		}
		out.RegistriesNotAnchored = append(out.RegistriesNotAnchored, reg.RegistrySAID)
	}
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
func (s *CoreServer) askForDiscardedApprovals(delegator string, seals []map[string]interface{}, out *discardedUnsignedEvents, ask bool) {
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
		if !ask {
			s.noteUnasked(out, a.ID, errors.New("the engine was not given the rewound key log"))
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
	if errors.Is(err, errEngineNotReloaded) {
		writeError(w, http.StatusInternalServerError, "set aside, engine not reloaded", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusConflict, "not discarded", err.Error())
		return
	}
	writeJSON(w, res)
}
