package keriengine

import (
	"encoding/json"
	"fmt"
	"time"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// Engine performs KERI operations in-process.
//
// It satisfies the same interface as the Python driver, so the core cannot tell
// which one it is holding — which is the point. The difference the core does
// feel is that this one exists on mobile.
type Engine struct {
	state   *state
	started time.Time
	// secrets is where a hybrid identity's private material is written.
	//
	// Optional, and used for nothing else. Ordinary KERI identities keep their
	// keys on the controller device and never present them here; a hybrid
	// identity is the one case where the engine generates key material, and it
	// has to be able to hand it somewhere durable or the identity it just
	// created is unusable.
	secrets keri.SecretStore
}

// New returns an engine with no identities, which is the state a cold start
// leaves it in. Identities arrive by being created or by being reloaded.
//
// An engine built this way refuses to create a real hybrid identity, because it
// has nowhere to put the private half. Everything else works.
func New() *Engine {
	return &Engine{state: newState()}
}

// NewWithSecretStore returns an engine that can create hybrid identities,
// writing their private material to the supplied store.
func NewWithSecretStore(secrets keri.SecretStore) *Engine {
	return &Engine{state: newState(), secrets: secrets}
}

// The engine is one of the implementations the core selects between.
var _ drivers.KeriEngine = (*Engine)(nil)

// Start records that the engine is running.
//
// Nothing is spawned and nothing can fail. The method exists because the
// interface carries it, and the interface carries it because the other
// implementation is a subprocess that genuinely has to be started — a core that
// had to know which kind it held would defeat the substitution.
func (e *Engine) Start() error {
	e.started = time.Now()
	return nil
}

// Stop releases nothing. See Start.
func (e *Engine) Stop() {}

func (e *Engine) GetStatus() (*drivers.DriverStatus, error) {
	uptime := ""
	if !e.started.IsZero() {
		uptime = time.Since(e.started).Round(time.Second).String()
	}
	return &drivers.DriverStatus{
		Status:      "active",
		Driver:      "keri-go",
		Version:     "1",
		KeriLibrary: "github.com/grapeid/keri-go",
		KeriVersion: keri.DefaultVersion.String(),
		ScriptPath:  "",
		Uptime:      uptime,
	}, nil
}

// CreateInception founds an identity with a generated name.
//
// The identifier is used as the name. An identity that has no name of its own
// still has to be findable later, and its identifier is the one label
// guaranteed to be unique and to already be known to the caller.
func (e *Engine) CreateInception(publicKey, nextPublicKey string) (*drivers.DriverInceptionResponse, error) {
	return e.incept(publicKey, nextPublicKey, "", nil)
}

// CreateInceptionNamed founds an identity under a caller-chosen name.
func (e *Engine) CreateInceptionNamed(publicKey, nextPublicKey, name string) (*drivers.DriverInceptionResponse, error) {
	return e.incept(publicKey, nextPublicKey, name, nil)
}

// CreateOwnedInception founds an identity that records who owns it.
//
// The owner is written into the inception event as anchored data, so ownership
// is established by the identity's own key log rather than by a record the
// agent keeps about it. An agent's account of who owns an identity is something
// the agent can be wrong about or lie about; the key log is neither.
func (e *Engine) CreateOwnedInception(publicKey, nextPublicKey, name, ownerAID string) (*drivers.DriverInceptionResponse, error) {
	if ownerAID == "" {
		return nil, fmt.Errorf("an owned identity needs an owner; without one this is an " +
			"ordinary inception and should be created as one")
	}
	// The owner is anchored as {"i": <owner>, "r": "owner"} — byte-for-byte what
	// the Python driver produces, so an identity founded here and one founded
	// there have the same identifier.
	//
	// That shape is NOT a KERI seal, and this is a known problem rather than an
	// oversight. The specification defines a closed set of seal shapes; a strict
	// reader parses this field as one of them and fails on anything else. An
	// independent implementation (keriox) cannot parse an inception carrying
	// this anchor at all — not "does not validate it", cannot read the event.
	// So an owned identity's inception is unreadable to such a reader, and
	// because it is the inception, the entire log is.
	//
	// It is reproduced here anyway, deliberately. Two things already read this
	// field back and match on "r" — see ownerRole in the server package — so
	// changing the shape changes the identifier of every owned identity AND
	// breaks the code that reads ownership. That is a decision about a published
	// format with existing consumers, not a detail for an engine to settle on
	// its own while porting.
	anchor := json.RawMessage(`{"i":` + quote(ownerAID) + `,"r":"owner"}`)
	return e.incept(publicKey, nextPublicKey, name, []json.RawMessage{anchor})
}

func (e *Engine) incept(publicKey, nextPublicKey, name string, data []json.RawMessage) (*drivers.DriverInceptionResponse, error) {
	pub, err := normaliseKey(publicKey, true)
	if err != nil {
		return nil, fmt.Errorf("the signing key: %w", err)
	}
	nextPub, err := normaliseKey(nextPublicKey, true)
	if err != nil {
		return nil, fmt.Errorf("the next signing key: %w", err)
	}
	if pub == nextPub {
		return nil, fmt.Errorf("the next key is the same as the current one; pre-rotation " +
			"would commit to the key already in use, so a compromise of it would also " +
			"carry the right to rotate")
	}
	// The commitment is a digest of the next key's qb64 TEXT, not of its raw
	// bytes and not the key itself. Committing to anything else produces a
	// rotation that every conformant implementation refuses, at the point where
	// the identity most needs to rotate.
	nextDigest, err := keri.NextDigest(nextPub)
	if err != nil {
		return nil, fmt.Errorf("committing to the next key: %w", err)
	}

	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{pub},
		NextDigests: []string{nextDigest},
		Data:        data,
		// Self-addressing: the identifier is a digest over the whole inception
		// event, so it commits to the witnesses and thresholds as well as the
		// key. A basic identifier is only the key, and an identity created that
		// way could not be reproduced from its own event.
		Derivation: "self-addressing",
	})
	if err != nil {
		return nil, fmt.Errorf("building the inception event: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, fmt.Errorf("the inception event this engine built does not parse: %w", err)
	}
	body, err := eventMap(raw)
	if err != nil {
		return nil, err
	}

	if name == "" {
		name = ev.Identifier
	}
	first, err := entry(raw)
	if err != nil {
		return nil, err
	}
	e.state.put(&identity{
		Name:            name,
		AID:             ev.Identifier,
		PublicKey:       pub,
		NextKeyDigest:   nextDigest,
		Witnesses:       ev.Witnesses,
		Toad:            witnessThreshold(ev),
		SN:              0,
		LastSAID:        ev.SAID,
		KEL:             []kelEntry{first},
		Registries:      map[string]*registry{},
		HistoryVerified: true,
	})

	return &drivers.DriverInceptionResponse{
		AID:            ev.Identifier,
		InceptionEvent: body,
		RawBytesB64:    b64(raw),
		PublicKey:      pub,
		NextKeyDigest:  nextDigest,
	}, nil
}

// CreateDelegatedInception founds an identity whose authority comes from
// another, and anchors the approval in the delegator's own log.
//
// Both halves are produced together. A delegated inception without the
// delegator's anchoring interaction is not a delegation at all — nothing has
// approved it — and returning one alone would let a caller publish an identity
// claiming an authority that was never granted.
func (e *Engine) CreateDelegatedInception(publicKey, nextPublicKey, name, delegatorName string) (*drivers.DriverDelegatedInceptionResponse, error) {
	delegator, err := e.state.get(delegatorName)
	if err != nil {
		return nil, fmt.Errorf("the delegator: %w", err)
	}
	pub, err := normaliseKey(publicKey, true)
	if err != nil {
		return nil, fmt.Errorf("the signing key: %w", err)
	}
	nextPub, err := normaliseKey(nextPublicKey, true)
	if err != nil {
		return nil, fmt.Errorf("the next signing key: %w", err)
	}
	nextDigest, err := keri.NextDigest(nextPub)
	if err != nil {
		return nil, err
	}

	dip, err := keri.BuildDelegatedInception(keri.DelegationInput{
		Keys:        []string{pub},
		NextDigests: []string{nextDigest},
		Delegator:   delegator.AID,
	})
	if err != nil {
		return nil, fmt.Errorf("building the delegated inception: %w", err)
	}
	dipEvent, err := keri.ParseEvent(dip)
	if err != nil {
		return nil, err
	}

	// The delegator anchors a seal naming the delegated event exactly: its
	// identifier, its sequence number and its digest. A seal that named only
	// the identifier would approve any event that identity ever produced.
	seal, err := eventSeal(dipEvent.Identifier, fmt.Sprintf("%x", dipEvent.SN), dipEvent.SAID)
	if err != nil {
		return nil, err
	}
	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    delegator.AID,
		PriorSAID: delegator.LastSAID,
		SN:        delegator.SN + 1,
		Data:      []json.RawMessage{seal},
	})
	if err != nil {
		return nil, fmt.Errorf("building the delegator's approval: %w", err)
	}
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, err
	}

	dipBody, err := eventMap(dip)
	if err != nil {
		return nil, err
	}
	ixnBody, err := eventMap(ixn)
	if err != nil {
		return nil, err
	}

	if name == "" {
		name = dipEvent.Identifier
	}
	first, err := entry(dip)
	if err != nil {
		return nil, err
	}
	e.state.put(&identity{
		Name:            name,
		AID:             dipEvent.Identifier,
		PublicKey:       pub,
		NextKeyDigest:   nextDigest,
		Witnesses:       dipEvent.Witnesses,
		Toad:            witnessThreshold(dipEvent),
		SN:              0,
		LastSAID:        dipEvent.SAID,
		KEL:             []kelEntry{first},
		Registries:      map[string]*registry{},
		HistoryVerified: true,
	})

	ixnEntry, err := entry(ixn)
	if err != nil {
		return nil, err
	}
	// The delegator's log only advances once its approval is recorded.
	e.state.mu.Lock()
	delegator.SN = int(ixnEvent.SN)
	delegator.LastSAID = ixnEvent.SAID
	delegator.KEL = append(delegator.KEL, ixnEntry)
	e.state.mu.Unlock()

	return &drivers.DriverDelegatedInceptionResponse{
		AID:           dipEvent.Identifier,
		DelegatorAID:  delegator.AID,
		Said:          dipEvent.SAID,
		DipEvent:      dipBody,
		DelegatorIxn:  ixnBody,
		RawBytesB64:   b64(dip),
		PublicKey:     pub,
		NextKeyDigest: nextDigest,
	}, nil
}

// RotateAid replaces an identity's signing key with the one it committed to.
func (e *Engine) RotateAid(name, newPublicKey, newNextPublicKey string) (*drivers.DriverRotationResponse, error) {
	return e.RotateAidWithAnchor(name, newPublicKey, newNextPublicKey, nil)
}

// RotateAidWithAnchor rotates and anchors data in the same event.
//
// One event, not two. Data anchored by a following interaction could be
// separated from the rotation by anyone relaying the log; data in the rotation
// itself is covered by the same digest and the same signature, so a reader
// either has both or has neither.
func (e *Engine) RotateAidWithAnchor(name, newPublicKey, newNextPublicKey string, anchorData []interface{}) (*drivers.DriverRotationResponse, error) {
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}
	newPub, err := normaliseKey(newPublicKey, true)
	if err != nil {
		return nil, fmt.Errorf("the new signing key: %w", err)
	}
	newNextPub, err := normaliseKey(newNextPublicKey, true)
	if err != nil {
		return nil, fmt.Errorf("the new next signing key: %w", err)
	}

	// The key being rotated to must be the one that was committed to. Checking
	// here turns a rotation that every other implementation would reject —
	// leaving the identity stranded with a published event nobody accepts —
	// into an error before anything is published.
	revealed, err := keri.NextDigest(newPub)
	if err != nil {
		return nil, err
	}
	if revealed != id.NextKeyDigest {
		return nil, fmt.Errorf("this key was not the one committed to: the identity committed "+
			"to %s and this key digests to %s. Rotating to it would produce an event no "+
			"conformant implementation accepts", id.NextKeyDigest, revealed)
	}
	newNextDigest, err := keri.NextDigest(newNextPub)
	if err != nil {
		return nil, err
	}

	anchors, err := rawData(anchorData)
	if err != nil {
		return nil, err
	}
	raw, err := keri.BuildRotation(keri.RotationInput{
		Prefix:         id.AID,
		Keys:           []string{newPub},
		PriorSAID:      id.LastSAID,
		SN:             id.SN + 1,
		NextDigests:    []string{newNextDigest},
		PriorWitnesses: id.Witnesses,
		Data:           anchors,
	})
	if err != nil {
		return nil, fmt.Errorf("building the rotation event: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	body, err := eventMap(raw)
	if err != nil {
		return nil, err
	}

	next, err := entry(raw)
	if err != nil {
		return nil, err
	}
	e.state.mu.Lock()
	id.PublicKey = newPub
	id.NextKeyDigest = newNextDigest
	id.SN = int(ev.SN)
	id.LastSAID = ev.SAID
	id.KEL = append(id.KEL, next)
	e.state.mu.Unlock()

	return &drivers.DriverRotationResponse{
		AID:              id.AID,
		NewPublicKey:     newPub,
		NewNextKeyDigest: newNextDigest,
		RotationEvent:    body,
		RawBytesB64:      b64(raw),
		Said:             ev.SAID,
		SequenceNumber:   int(ev.SN),
	}, nil
}

// RotateToMultisig rotates an identity from one signer to several.
//
// The next-key digests are supplied already digested, because the keys they
// commit to belong to the other members and must not be revealed here.
func (e *Engine) RotateToMultisig(name string, keys, nextKeyDigests []string, isith, nsith string, anchorData []interface{}) (*drivers.DriverRotationResponse, error) {
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("a multisig rotation needs at least one key")
	}
	if len(nextKeyDigests) == 0 {
		return nil, fmt.Errorf("a multisig rotation with no next-key commitments would leave " +
			"the group unable to ever rotate again")
	}
	normalised := make([]string, 0, len(keys))
	for i, k := range keys {
		n, err := normaliseKey(k, true)
		if err != nil {
			return nil, fmt.Errorf("member key %d: %w", i, err)
		}
		normalised = append(normalised, n)
	}
	data, err := rawData(anchorData)
	if err != nil {
		return nil, err
	}

	in := keri.RotationInput{
		Prefix:         id.AID,
		Keys:           normalised,
		PriorSAID:      id.LastSAID,
		SN:             id.SN + 1,
		NextDigests:    nextKeyDigests,
		PriorWitnesses: id.Witnesses,
		Data:           data,
	}
	// A threshold is only written when one was asked for; the builder derives
	// the default otherwise, and a value written here would be the caller's
	// guess at that default rather than the default itself.
	if isith != "" {
		in.Isith = thresholdJSON(isith)
	}
	if nsith != "" {
		in.Nsith = thresholdJSON(nsith)
	}

	raw, err := keri.BuildRotation(in)
	if err != nil {
		return nil, fmt.Errorf("building the multisig rotation: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	body, err := eventMap(raw)
	if err != nil {
		return nil, err
	}

	next, err := entry(raw)
	if err != nil {
		return nil, err
	}
	e.state.mu.Lock()
	id.PublicKey = normalised[0]
	id.NextKeyDigest = nextKeyDigests[0]
	id.SN = int(ev.SN)
	id.LastSAID = ev.SAID
	id.KEL = append(id.KEL, next)
	e.state.mu.Unlock()

	return &drivers.DriverRotationResponse{
		AID:              id.AID,
		NewPublicKey:     normalised[0],
		NewNextKeyDigest: nextKeyDigests[0],
		Keys:             normalised,
		NextKeyDigests:   nextKeyDigests,
		Isith:            isith,
		Nsith:            nsith,
		RotationEvent:    body,
		RawBytesB64:      b64(raw),
		Said:             ev.SAID,
		SequenceNumber:   int(ev.SN),
	}, nil
}

// Interact anchors data in an identity's key log.
func (e *Engine) Interact(name string, data []interface{}) (*drivers.DriverInteractResponse, error) {
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}
	anchors, err := rawData(data)
	if err != nil {
		return nil, err
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("an interaction with nothing to anchor would extend the log " +
			"without recording anything")
	}
	raw, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    id.AID,
		PriorSAID: id.LastSAID,
		SN:        id.SN + 1,
		Data:      anchors,
	})
	if err != nil {
		return nil, fmt.Errorf("building the interaction event: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	body, err := eventMap(raw)
	if err != nil {
		return nil, err
	}

	next, err := entry(raw)
	if err != nil {
		return nil, err
	}
	e.state.mu.Lock()
	id.SN = int(ev.SN)
	id.LastSAID = ev.SAID
	id.KEL = append(id.KEL, next)
	e.state.mu.Unlock()

	return &drivers.DriverInteractResponse{
		AID:            id.AID,
		IxnEvent:       body,
		RawBytesB64:    b64(raw),
		Said:           ev.SAID,
		SequenceNumber: int(ev.SN),
	}, nil
}

// GetKel returns an identity's key log, parsed and raw.
//
// Both forms, because they answer different questions and neither substitutes
// for the other: the parsed events are readable, and only the raw bytes can be
// verified against.
func (e *Engine) GetKel(name string) (*drivers.DriverKelResponse, error) {
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}
	e.state.mu.RLock()
	defer e.state.mu.RUnlock()

	events := make([]map[string]interface{}, 0, len(id.KEL))
	// An entry with no canonical bytes yields an empty string rather than a
	// re-encoding of the parsed event. A re-encoding would be the right length
	// and the wrong digest, and a caller checking a signature against it would
	// get a confident, wrong answer; an empty string cannot be mistaken for an
	// event.
	rawB64 := make([]string, 0, len(id.KEL))
	for _, ev := range id.KEL {
		events = append(events, ev.Parsed)
		if ev.Raw == nil {
			rawB64 = append(rawB64, "")
			continue
		}
		rawB64 = append(rawB64, b64(ev.Raw))
	}
	return &drivers.DriverKelResponse{
		AID:            id.AID,
		KEL:            events,
		RawEventsB64:   rawB64,
		SequenceNumber: id.SN,
		EventCount:     len(id.KEL),
	}, nil
}

// ReloadIdentity restores an identity the agent already has on record.
//
// The engine starts empty, so an agent that has been restarted hands back what
// it persisted. Where the canonical bytes were kept, the whole log is validated
// before it is accepted: it comes from the agent's own storage, and storage
// that has been corrupted or edited should fail here rather than at the point
// where the identity next publishes something.
//
// Where they were not kept — events stored before the raw form was recorded —
// the identity is still restored, because refusing would strand a real identity
// whose log is intact but unverifiable by this engine. What is NOT done is to
// rebuild the bytes by re-encoding the parsed events: that produces a different
// field order, hence a different digest, and would manufacture a log that looks
// verified and is not. The identity is marked as having an unverified history
// instead, and says so.
func (e *Engine) ReloadIdentity(req *drivers.DriverReloadIdentityRequest) (*drivers.DriverReloadIdentityResponse, error) {
	if req == nil || req.AID == "" {
		return nil, fmt.Errorf("reloading an identity needs its identifier")
	}
	if len(req.KEL) == 0 {
		return nil, fmt.Errorf("reloading %s with an empty key log would create an identity "+
			"with no history, which would then fork the real one at its next event", req.AID)
	}

	entries := make([]kelEntry, 0, len(req.KEL))
	for i, parsed := range req.KEL {
		e := kelEntry{Parsed: parsed}
		if i < len(req.RawEventsB64) && req.RawEventsB64[i] != "" {
			raw, err := decodeB64(req.RawEventsB64[i])
			if err != nil {
				return nil, fmt.Errorf("event %d of %s has unreadable stored bytes: %w", i, req.AID, err)
			}
			// The stored bytes must be the event the stored record claims.
			// Checking here catches a record whose two halves have drifted
			// apart, which would otherwise surface as an unverifiable log much
			// later.
			ev, err := keri.ParseEvent(raw)
			if err != nil {
				return nil, fmt.Errorf("event %d of %s does not parse as a KERI event: %w", i, req.AID, err)
			}
			if d, ok := parsed["d"].(string); ok && d != "" && d != ev.SAID {
				return nil, fmt.Errorf("event %d of %s is stored twice and the copies disagree: "+
					"the parsed form says %s and the bytes digest to %s", i, req.AID, d, ev.SAID)
			}
			e.Raw = raw
		}
		entries = append(entries, e)
	}

	raws, complete := verifiable(entries)
	if complete {
		if err := keri.ValidateKEL(raws); err != nil {
			return nil, fmt.Errorf("the stored key log for %s does not validate, so it is not "+
				"the log this identity published: %w", req.AID, err)
		}
	}

	// The tip is what the next event chains to. Taken from the raw form when
	// there is one, and from the stored fields otherwise.
	sn, lastSAID := req.SequenceNumber, req.LastSAID
	var witnesses []string
	toad := 0
	if last := entries[len(entries)-1]; last.Raw != nil {
		ev, err := keri.ParseEvent(last.Raw)
		if err != nil {
			return nil, err
		}
		sn, lastSAID = int(ev.SN), ev.SAID
		witnesses, toad = ev.Witnesses, witnessThreshold(ev)
	}
	if lastSAID == "" {
		return nil, fmt.Errorf("reloading %s needs the digest of its most recent event; "+
			"without it the next event cannot name its predecessor", req.AID)
	}

	pub := req.PublicKey
	if pub != "" {
		var err error
		if pub, err = normaliseKey(pub, true); err != nil {
			return nil, fmt.Errorf("the stored signing key: %w", err)
		}
	}

	e.state.put(&identity{
		Name:            req.AID,
		AID:             req.AID,
		PublicKey:       pub,
		NextKeyDigest:   req.NextKeyDigest,
		Witnesses:       witnesses,
		Toad:            toad,
		SN:              sn,
		LastSAID:        lastSAID,
		KEL:             entries,
		Registries:      map[string]*registry{},
		HistoryVerified: complete,
	})

	status := "reloaded"
	if !complete {
		// Said plainly in the response rather than logged, because a caller
		// that believes a log was verified when it was not is exactly the
		// mistake this is here to prevent.
		status = "reloaded; history not verified because the stored log predates " +
			"canonical bytes being kept"
	}
	return &drivers.DriverReloadIdentityResponse{
		AID:            req.AID,
		SequenceNumber: sn,
		KelEvents:      len(entries),
		Status:         status,
	}, nil
}
