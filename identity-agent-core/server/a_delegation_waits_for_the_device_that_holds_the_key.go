package server

// A delegated identity approved by the device that holds the identity's key.
//
// Making an AI agent, an app or any other identity delegated from the owner
// writes the owner's approval of it into the owner's key log, as an
// interaction only the owner's key can sign. Where that key is on another
// device, the inception and the approval are built here and kept, the asset is
// stored unable to act (asset.Asset.ApprovalPending), and the interaction is
// queued for that device as a "delegation-approval" request, with the
// delegated inception, so the device can check what it signs
// (authorisation.WhatSigningApproves) and show what the inception itself says.
//
// It is chained ahead of the registry and the grant as the registry is chained
// ahead of the grant: while it waits, whatever is asked for the asset is kept
// behind it, and built once the approval has landed. When the signature comes
// back it must be over the interaction kept; only then is the approval
// appended, the asset let act, and the next thing behind it asked for. Nothing
// is written into the key log unsigned.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/authorisation"
	"identity-agent-core/drivers"
)

// signingKindDelegation is the signing request for the interaction that
// approves a delegated identity.
const signingKindDelegation = "delegation-approval"

// askApproval asks the device that holds the identity's key to approve a
// delegated identity, for an asset already stored with its approval pending.
func (s *CoreServer) askApproval(a asset.Asset, p *drivers.PreparedDelegation) error {
	shown, err := authorisation.WhatSigningApproves(p.IxnRaw, p.DipRaw)
	if err != nil {
		return err
	}
	_, err = s.queueForTheKey(signingKindDelegation, pendingIssuance{Kind: signingKindDelegation,
		Spec: grantSpec{Issuer: p.Delegator}, Delegation: p, AssetID: a.ID}, p.IxnRaw, summaryOf(shown))
	return err
}

// askApprovalAgain builds again, and asks for, the approval of an asset whose
// approval is pending, as it is when what was asked has been withdrawn, has
// expired, or was built on a key log that has moved on.
func (s *CoreServer) askApprovalAgain(assetID string) error {
	if s.assetHandler == nil {
		return fmt.Errorf("no assets are held here")
	}
	a, ok, err := s.assetHandler.Store.GetAsset(assetID)
	if err != nil {
		return err
	}
	if !ok || !a.ApprovalPending {
		return nil
	}
	p, err := s.assetHandler.PrepareApprovalOf(a)
	if err != nil {
		return err
	}
	return s.askApproval(a, p)
}

// adoptDelegation appends the approval the device signed and lets the asset
// act. Signed by the device that holds the key it is in that device's key log
// already, so it is taken up here whatever has changed since it was asked for;
// an asset removed meanwhile is simply left approved.
func (s *CoreServer) adoptDelegation(row waitingRow, signature string) error {
	p := row.Pending
	preparer, ok := s.KeriDriver.(drivers.PreparedDelegator)
	if !ok {
		return fmt.Errorf("this engine cannot append a prepared delegation")
	}
	var a asset.Asset
	var held bool
	if s.assetHandler != nil {
		var err error
		if a, held, err = s.assetHandler.Store.GetAsset(p.AssetID); err != nil {
			return err
		}
	}
	asked := s.stillAsked(row)
	if !held || !a.ApprovalPending {
		// Nothing here waits for it any more: the device's key log has it, so
		// this one takes it up as it is.
		if err := s.adoptBare(p.Delegation.Delegator, p.Delegation.IxnRaw, signature); err != nil {
			return err
		}
	} else {
		keep := func(k drivers.KELKeep) error {
			var parsed map[string]interface{}
			if err := json.Unmarshal(k.Raw, &parsed); err != nil {
				return err
			}
			rec, err := s.ownInteractionRecord(p.Delegation.Delegator, parsed, base64.StdEncoding.EncodeToString(k.Raw), k.SN, k.Signature)
			if err != nil {
				return err
			}
			return s.DataStore.SaveEvent(rec)
		}
		if err := s.withSignature(p.Delegation.IxnRaw, signature, func() error {
			_, err := preparer.AppendPreparedDelegation(p.Delegation.Delegator, a.DisplayName, p.Delegation, keep,
				asset.FoundingSigner(s.DataDir, a.SigningIndex))
			return err
		}); err != nil {
			return err
		}
		a.ApprovalPending, a.UpdatedAt = false, time.Now().UTC()
		if err := s.assetHandler.Store.UpsertAsset(a); err != nil {
			return fmt.Errorf("the approval is appended, and %q could not be let act: %w", a.DisplayName, err)
		}
	}
	_ = s.DataStore.DeletePendingIssuance(row.ID)
	if asked {
		s.markSigned(row.ID)
	} else {
		s.closeExpired(row.ID)
	}
	return nil
}

func (s *CoreServer) completeDelegation(requestID string, pending pendingIssuance, signature string) error {
	if _, err := authorisation.WhatSigningApproves(pending.Delegation.IxnRaw, pending.Delegation.DipRaw); err != nil {
		return err
	}
	err := s.adoptDelegation(waitingRow{ID: requestID, Pending: pending}, signature)
	if errors.Is(err, drivers.ErrStalePreparation) {
		// Built on a key log that has moved on: built again and asked afresh.
		_ = s.DataStore.DeletePendingIssuance(requestID)
		if aerr := s.askApprovalAgain(pending.AssetID); aerr != nil {
			return fmt.Errorf("%w, and it could not be built again: %v", err, aerr)
		}
		return fmt.Errorf("%w; it has been built again and asked for afresh", err)
	}
	if err != nil {
		return fmt.Errorf("the delegation was not approved: %w", err)
	}
	s.witnessOwnLog()
	s.buildNextBehind()
	return nil
}

// delegationRefused takes back an asset whose approval the device refused: it
// was never approved, so nothing in any key log names it, and what was kept
// behind its approval is dropped with it.
func (s *CoreServer) delegationRefused(requestID string) {
	body, ok, err := s.DataStore.GetPendingIssuance(requestID)
	if err != nil || !ok {
		return
	}
	var p pendingIssuance
	if json.Unmarshal([]byte(body), &p) != nil || p.AssetID == "" {
		return
	}
	_ = s.DataStore.DeletePendingIssuance(requestID)
	if s.assetHandler == nil {
		return
	}
	a, held, err := s.assetHandler.Store.GetAsset(p.AssetID)
	if err != nil || !held || !a.ApprovalPending {
		return
	}
	s.withdrawWaitingFor(a.PairwiseAID)
	for _, row := range s.waitingRows() {
		if row.Pending.Kind == waitingBehind && row.Pending.Spec.Holder == a.PairwiseAID {
			_ = s.DataStore.DeletePendingIssuance(row.ID)
		}
	}
	if err := s.assetHandler.Store.DeleteAsset(a.ID); err != nil {
		log.Printf("[grants] %q was refused its approval and could not be removed: %v", a.DisplayName, err)
		return
	}
	log.Printf("[grants] %q was refused its approval by the device that holds the key, and is removed", a.DisplayName)
}

// handleAskApprovalAgain asks the device that holds the key again for the
// approval of an asset still waiting for it, as when the request expired.
func (s *CoreServer) handleAskApprovalAgain(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "only this agent's owner asks for it")
		return
	}
	a, ok, err := s.assetHandler.Store.GetAsset(chi.URLParam(r, "id"))
	if err != nil || !ok {
		writeError(w, http.StatusNotFound, "no such asset", "")
		return
	}
	if !a.ApprovalPending {
		writeError(w, http.StatusConflict, "nothing to approve", a.DisplayName+" is not waiting for its approval")
		return
	}
	if err := s.askApprovalAgain(a.ID); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, errAlreadyAsked) {
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, "not asked", err.Error())
		return
	}
	writeJSON(w, map[string]any{"asked": true, "asset": a.ID})
}
