package asset

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// A delegated asset made where the identity's key is held on another device.
//
// The delegated identity is approved by an interaction in the delegator's key
// log, which only the device holding the key can sign. Here the asset is
// stored at once, with the identifier its inception derives and its approval
// pending, and the device is asked to sign the approval. Until it is appended
// the asset cannot act (Asset.ApprovalPending), and nothing is written into
// the key log unsigned. The grant that follows is issued by the caller as
// before; it is kept behind the approval and asked for once that has landed.

// mustAskTheKeyDevice says whether the approval of a delegated identity is to
// be asked of another device, because this one does not hold the identity's
// key. An error is returned where it cannot be made here at all: the key is
// held here and cannot be read, or the other device cannot be asked.
func (h *Handler) mustAskTheKeyDevice() (bool, error) {
	err := h.mayDelegate()
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, ErrKeyElsewhere) && h.AskApproval != nil:
		if _, can := h.KeriDriver.(drivers.PreparedDelegator); can {
			return true, nil
		}
	}
	return false, err
}

// prepareApproval builds the inception of a delegated identity over these
// keys, and the delegator's interaction approving it, holding neither.
func (h *Handler) prepareApproval(rootAID, pub, nextPub string) (*drivers.PreparedDelegation, error) {
	preparer, can := h.KeriDriver.(drivers.PreparedDelegator)
	if !can {
		return nil, ErrKeyElsewhere
	}
	p, err := preparer.PrepareDelegatedInception(rootAID, pub, nextPub, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("prepare the delegated identity: %w", err)
	}
	return p, nil
}

// PrepareApprovalOf builds, again, the approval of a delegated asset made by
// this agent whose approval is pending: its keys are re-derived, so the
// inception is the one it was made with.
func (h *Handler) PrepareApprovalOf(a Asset) (*drivers.PreparedDelegation, error) {
	if !a.ApprovalPending || a.DelegatorAID == "" || a.SigningIndex == 0 {
		return nil, fmt.Errorf("%s is not an asset waiting for its approval", a.DisplayName)
	}
	pub, nextPub, err := deriveAssetKeypair(h.dataDir, a.SigningIndex)
	if err != nil {
		return nil, fmt.Errorf("derive the key of %s: %w", a.DisplayName, err)
	}
	p, err := h.prepareApproval(a.DelegatorAID, iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(nextPub))
	if err != nil {
		return nil, err
	}
	if p.AID != a.PairwiseAID {
		return nil, fmt.Errorf("the approval prepared is of %s, not of %s", p.AID, a.PairwiseAID)
	}
	return p, nil
}

// storeAwaitingApproval stores a, whose approval is pending, and asks for the
// approval. If it cannot be asked the asset is removed again: nothing was
// written to the key log, so nothing else needs undoing.
func (h *Handler) storeAwaitingApproval(a Asset, p *drivers.PreparedDelegation) error {
	if err := h.Store.UpsertAsset(a); err != nil {
		return err
	}
	if err := h.AskApproval(a, p); err != nil {
		_ = h.Store.DeleteAsset(a.ID)
		return fmt.Errorf("the approval could not be asked of the device that holds the key: %w", err)
	}
	return nil
}

func (h *Handler) provisionAwaitingApproval(d delegatedAsset, id string, signingIndex int, rootAID, displayName string,
	pub, nextPub ed25519.PublicKey) (*Asset, error) {
	p, err := h.prepareApproval(rootAID, iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(nextPub))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	a := Asset{
		ID:               id,
		DisplayName:      displayName,
		AssetType:        d.assetType,
		Origin:           d.originScheme + "://" + id,
		PairwiseAID:      p.AID,
		DelegationModel:  "delegated",
		DelegatorAID:     rootAID,
		ApprovalPending:  true,
		SigningIndex:     signingIndex,
		Capabilities:     d.capabilities,
		AgentConfig:      d.cfg,
		GrantValidUntil:  d.validUntil,
		GrantConstraints: d.constraints,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := h.storeAwaitingApproval(a, p); err != nil {
		return nil, err
	}
	return &a, nil
}
