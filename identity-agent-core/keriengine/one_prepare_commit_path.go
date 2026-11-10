package keriengine

import (
	"bytes"
	"encoding/json"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// Every event that anchors something is prepared and committed one way.
//
// A registry's inception, an issuance, a revocation and a delegator's approval
// of a delegated identity are each an interaction in the issuer's key log
// that anchors one seal, built beside the event it anchors. What differs
// between them is only what the seal names, so that is the only thing each
// kind says (an anchorCheck); the interaction is built by Prepare and added by
// Commit, as any other is (ADR-061 section 3).

// anchorCheck is one kind's judgement of what a prepared pair anchors. It
// verifies the event the interaction is prepared with and returns the seal
// naming it exactly, which the interaction must carry and no other.
type anchorCheck func() (json.RawMessage, error)

// anchoredEvent is a prepared interaction and the one kind-specific part of
// committing it.
type anchoredEvent struct {
	// Prior, SN, IxnRaw and IxnSAID are the interaction as it was prepared.
	Prior   string
	SN      int
	IxnRaw  []byte
	IxnSAID string
	// Check says what the interaction must anchor.
	Check anchorCheck
	// Mismatch is what a refusal says when the interaction anchors anything
	// else, naming the kind.
	Mismatch string
	// Sign has the interaction signed, and returns the keep that offers the
	// event for keeping alongside it, or nil.
	Sign func(ixn []byte, sn uint64) (string, func(drivers.KELKeep) error, error)
	// Also runs, under the state lock, for what else the event changes.
	Also func()
}

// prepareAnchoring builds the interaction anchoring seal on id's key log as it
// stands now, and adds nothing. It returns the interaction, parsed, and the
// event it follows.
func (e *Engine) prepareAnchoring(id *identity, seal json.RawMessage) ([]byte, *keri.Event, string, error) {
	p, err := e.prepareFor(id, PrepareRequest{Ilk: "ixn", Anchors: []json.RawMessage{seal}})
	if err != nil {
		return nil, nil, "", err
	}
	ev, err := keri.ParseEvent(p.Raw)
	if err != nil {
		return nil, nil, "", err
	}
	return p.Raw, ev, p.Hint.P, nil
}

// commitAnchored adds a prepared interaction exactly as prepared, while it
// still extends the tip of id's key log: the stale-tip check, the
// re-derivation of the interaction from what it must anchor, the signature,
// and Commit. The caller holds id for writing.
func (e *Engine) commitAnchored(id *identity, a anchoredEvent) (*keri.Event, error) {
	e.state.mu.RLock()
	tipSAID, tipSN := id.LastSAID, id.SN
	e.state.mu.RUnlock()
	if a.Prior != tipSAID || a.SN != tipSN+1 {
		return nil, drivers.ErrStalePreparation
	}
	seal, err := a.Check()
	if err != nil {
		return nil, err
	}
	// What is added is derived again from what it must anchor, never taken
	// from the pair's own fields: the pair would otherwise be added as proof
	// of each other when it is not.
	want, err := e.prepareFor(id, PrepareRequest{Ilk: "ixn", Anchors: []json.RawMessage{seal},
		After: &Place{SN: a.SN - 1, SAID: a.Prior}})
	if err != nil || !bytes.Equal(want.Raw, a.IxnRaw) {
		return nil, fmt.Errorf("%s", a.Mismatch)
	}
	ixnEvent, err := keri.ParseEvent(a.IxnRaw)
	if err != nil || ixnEvent.SAID != a.IxnSAID || int(ixnEvent.SN) != a.SN {
		return nil, fmt.Errorf("the prepared interaction is not what was prepared")
	}
	sig, keep, err := a.Sign(a.IxnRaw, ixnEvent.SN)
	if err != nil {
		return nil, err
	}
	e.state.mu.RLock()
	key := id.PublicKey
	e.state.mu.RUnlock()
	if err := verifiedBy(id.AID, key, a.IxnRaw, sig); err != nil {
		return nil, err
	}
	var kept func(drivers.KELKeep) error
	if keep != nil {
		kept = func(k drivers.KELKeep) error {
			k.Signature = sig
			return keep(k)
		}
	}
	if _, err := e.commitHeld(id, ixnEvent, a.IxnRaw, []string{sig}, kept,
		commitOptions{also: a.Also, refuseWaiting: true}); err != nil {
		return nil, err
	}
	return ixnEvent, nil
}

// signedByEngine has the interaction signed as this engine has the identity's
// events signed, with nothing to keep beside it.
func (e *Engine) signedByEngine(id *identity) func([]byte, uint64) (string, func(drivers.KELKeep) error, error) {
	return func(ixn []byte, _ uint64) (string, func(drivers.KELKeep) error, error) {
		sig, err := e.signed(id, ixn)
		return sig, nil, err
	}
}

// signedWithTEL has the interaction signed and offers it for keeping with the
// registry event it anchors.
func (e *Engine) signedWithTEL(id *identity, tel []byte) func([]byte, uint64) (string, func(drivers.KELKeep) error, error) {
	return func(ixn []byte, sn uint64) (string, func(drivers.KELKeep) error, error) {
		return e.commit(id, sn, ixn, tel)
	}
}
