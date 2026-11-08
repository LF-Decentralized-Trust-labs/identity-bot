package keriengine

import (
	"bytes"
	"encoding/json"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// A delegated identity is built, then added, as an issuance is.
//
// Making an identity delegated from another needs the delegator to approve it
// by an interaction in its own key log, and only whoever holds the delegator's
// key can sign that. Where that is another device, the inception and the
// approval are built first and added only when the signature comes back, so
// the approval is never written unsigned. Making one where the key is held
// here is the same two steps run together (CreateDelegatedInceptionKept), so
// there is one way the approval is built and one way it is added.

// PrepareDelegatedInception builds the inception of an identity delegated by
// delegatorName over these keys, and the delegator's interaction approving it,
// on the delegator's key log as it stands now, without adding or holding
// either.
func (e *Engine) PrepareDelegatedInception(delegatorName, publicKey, nextPublicKey string, witnesses []string, toad int) (*drivers.PreparedDelegation, error) {
	delegator, release, err := e.holdForWriting(delegatorName)
	if err != nil {
		return nil, fmt.Errorf("the delegator: %w", err)
	}
	defer release()
	return e.prepareDelegation(delegator, publicKey, nextPublicKey, witnesses, toad)
}

// AppendPreparedDelegation adds a delegator's approval exactly as it was
// prepared, signed as this engine has the delegator's events signed, while it
// still extends the delegator's key log's tip; then holds the delegated
// identity under name.
func (e *Engine) AppendPreparedDelegation(delegatorName, name string, p *drivers.PreparedDelegation, keep func(drivers.KELKeep) error, sign ...drivers.FoundingSigner) (*drivers.DriverDelegatedInceptionResponse, error) {
	delegator, release, err := e.holdForWriting(delegatorName)
	if err != nil {
		return nil, fmt.Errorf("the delegator: %w", err)
	}
	defer release()
	return e.appendDelegation(delegator, name, p, keep, sign...)
}

func (e *Engine) prepareDelegation(delegator *identity, publicKey, nextPublicKey string, witnesses []string, toad int) (*drivers.PreparedDelegation, error) {
	pub, nextDigest, dip, dipEvent, err := delegatedInceptionOver(publicKey, nextPublicKey, delegator.AID, witnesses, toad)
	if err != nil {
		return nil, err
	}
	e.state.mu.RLock()
	prior, sn := delegator.LastSAID, delegator.SN+1
	e.state.mu.RUnlock()
	ixn, ixnEvent, err := delegatorApproval(delegator.AID, prior, sn, dipEvent)
	if err != nil {
		return nil, err
	}
	return &drivers.PreparedDelegation{Delegator: delegator.AID, AID: dipEvent.Identifier, DipRaw: dip, DipSAID: dipEvent.SAID,
		PublicKey: pub, NextKeyDigest: nextDigest, IxnRaw: ixn, IxnSAID: ixnEvent.SAID, SN: int(ixnEvent.SN), Prior: prior}, nil
}

// delegatorApproval builds the delegator's interaction approving dipEvent.
//
// The delegator anchors a seal naming the delegated event exactly: its
// identifier, its sequence number and its digest. A seal that named only the
// identifier would approve any event that identity ever produced.
func delegatorApproval(delegatorAID, prior string, sn int, dipEvent *keri.Event) ([]byte, *keri.Event, error) {
	seal, err := eventSeal(dipEvent.Identifier, fmt.Sprintf("%x", dipEvent.SN), dipEvent.SAID)
	if err != nil {
		return nil, nil, err
	}
	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    delegatorAID,
		PriorSAID: prior,
		SN:        sn,
		Data:      []json.RawMessage{seal},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("building the delegator's approval: %w", err)
	}
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, nil, err
	}
	return ixn, ixnEvent, nil
}

func (e *Engine) appendDelegation(delegator *identity, name string, p *drivers.PreparedDelegation, keep func(drivers.KELKeep) error, sign ...drivers.FoundingSigner) (*drivers.DriverDelegatedInceptionResponse, error) {
	if p == nil || p.Delegator != delegator.AID {
		return nil, fmt.Errorf("the prepared delegation is not this identity's")
	}
	e.state.mu.RLock()
	tipSAID, tipSN := delegator.LastSAID, delegator.SN
	e.state.mu.RUnlock()
	if p.Prior != tipSAID || p.SN != tipSN+1 {
		return nil, drivers.ErrStalePreparation
	}
	// What is added is derived again from the inception, never taken from the
	// fields beside it.
	if err := keri.ValidateEvent(p.DipRaw); err != nil {
		return nil, fmt.Errorf("the prepared inception is not what it says it is: %w", err)
	}
	dipEvent, err := keri.ParseEvent(p.DipRaw)
	if err != nil {
		return nil, err
	}
	if dipEvent.Ilk != "dip" || dipEvent.Delegator != delegator.AID || dipEvent.Identifier != p.AID || dipEvent.SAID != p.DipSAID ||
		len(dipEvent.Keys) != 1 || len(dipEvent.NextDigest) != 1 {
		return nil, fmt.Errorf("the prepared inception is not a delegation from %s", delegator.AID)
	}
	ixn, _, err := delegatorApproval(delegator.AID, p.Prior, p.SN, dipEvent)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ixn, p.IxnRaw) {
		return nil, fmt.Errorf("the prepared interaction does not approve the prepared inception")
	}
	pub, nextDigest, dip := dipEvent.Keys[0], dipEvent.NextDigest[0], p.DipRaw

	dipBody, err := eventMap(dip)
	if err != nil {
		return nil, err
	}
	ixnBody, err := eventMap(ixn)
	if err != nil {
		return nil, err
	}
	approvalSig, err := e.signed(delegator, ixn)
	if err != nil {
		return nil, err
	}
	// The delegated founding is signed like any other, or nothing is made: an
	// approval kept for an identity that cannot be signed would approve nothing.
	dipSigs, err := e.signedFounding(dipEvent, dip, firstSigner(sign))
	if err != nil {
		return nil, err
	}
	// The name must be free before anything is kept, or the store would hold a
	// delegation the engine then refuses to.
	heldAs := name
	if heldAs == "" {
		heldAs = dipEvent.Identifier
	}
	if held, err := e.state.get(heldAs); err == nil && held.AID != dipEvent.Identifier {
		return nil, fmt.Errorf("the name %q already holds %s", heldAs, held.AID)
	}
	var kept func(drivers.KELKeep) error
	if keep != nil {
		kept = func(k drivers.KELKeep) error {
			k.Delegated = dip
			if err := keep(k); err != nil {
				return fmt.Errorf("the delegation was not kept, so it was not made: %w", err)
			}
			return nil
		}
	}
	// The delegator's approval first, kept once the delegator's log with it
	// has been judged; only then is the delegated identity held.
	if err := e.extend(delegator, ixn, approvalSig, kept, nil); err != nil {
		return nil, err
	}
	if err := e.holdDelegatedIdentity(name, pub, nextDigest, dip, dipEvent, dipSigs); err != nil {
		return nil, err
	}
	return &drivers.DriverDelegatedInceptionResponse{
		AID:          dipEvent.Identifier,
		DelegatorAID: delegator.AID,
		Said:         dipEvent.SAID,
		DipEvent:     dipBody,
		DelegatorIxn: ixnBody,
		RawBytesB64:  b64(dip),

		DelegatorIxnRawBytesB64: b64(ixn),
		PublicKey:               pub,
		NextKeyDigest:           nextDigest,
	}, nil
}
