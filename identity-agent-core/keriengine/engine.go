package keriengine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"

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
	// http is how OOBIs are fetched. Replaceable so a test needs no network.
	http HTTPClient

	// writing holds one lock per identity, taken from reading its tip to
	// appending the event built on it. Without it two events built at once on
	// the same tip both chain to it, and the log forks.
	writing sync.Map
	// telCommit keeps a registry event and its anchor before the engine
	// appends them; see drivers.TELCommitter.
	commitMu  sync.Mutex
	telCommit func(drivers.TELCommit) error
	// eventSignature signs an interaction about to be appended to an
	// identity's own key log; see SetEventSignature.
	eventSignature func(aid, key string, raw []byte) (string, error)
}

// SetEventSignature installs how this engine obtains an identity's signature
// over an interaction it is about to append to that identity's key log.
//
// Every interaction this engine appends to a key log is signed by that
// identity's current key, checked here, or it is not appended: in one place,
// so no path that writes into a key log can leave there an event the key
// never signed. With nothing installed, nothing is appended.
func (e *Engine) SetEventSignature(f func(aid, key string, raw []byte) (string, error)) {
	e.commitMu.Lock()
	e.eventSignature = f
	e.commitMu.Unlock()
}

// signed is id's signature over raw, checked against its current key.
func (e *Engine) signed(id *identity, raw []byte) (string, error) {
	e.commitMu.Lock()
	f := e.eventSignature
	e.commitMu.Unlock()
	if f == nil {
		return "", fmt.Errorf("this engine has no way to have events of %s signed, so it appends none", id.AID)
	}
	e.state.mu.RLock()
	key := id.PublicKey
	e.state.mu.RUnlock()
	if key == "" {
		return "", verifiedBy(id.AID, key, raw, "")
	}
	sig, err := f(id.AID, key, raw)
	if err != nil {
		return "", fmt.Errorf("the event was not signed by %s, so it is not appended: %w", id.AID, err)
	}
	if err := verifiedBy(id.AID, key, raw, sig); err != nil {
		return "", err
	}
	return sig, nil
}

// SetHTTPClient replaces how this engine fetches introductions.
func (e *Engine) SetHTTPClient(c HTTPClient) { e.http = c }

// New returns an engine with no identities, which is the state a cold start
// leaves it in. Identities arrive by being created or by being reloaded.
//
// An engine built this way refuses to create a real hybrid identity, because it
// has nowhere to put the private half. Everything else works.
func New() *Engine {
	return &Engine{state: newState(), eventSignature: testEventSignature}
}

// NewWithSecretStore returns an engine that can create hybrid identities,
// writing their private material to the supplied store.
func NewWithSecretStore(secrets keri.SecretStore) *Engine {
	return &Engine{state: newState(), secrets: secrets, eventSignature: testEventSignature}
}

// testEventSignature is nil outside this package's own tests, which set it to
// sign with the keys they made.
var testEventSignature func(aid, key string, raw []byte) (string, error)

// The engine is one of the implementations the core selects between.
var _ drivers.KeriEngine = (*Engine)(nil)

// It keeps an event before appending it when asked to.
var _ drivers.KELKeeper = (*Engine)(nil)

// Start records that the engine is running.
//
// Nothing is spawned and nothing can fail. The method exists because the
// interface carries it, and the interface carries it because the other
// implementation is a subprocess that genuinely has to be started — a core that
// had to know which kind it held would defeat the substitution.
// SetTELCommit installs the function that keeps a registry event and its
// anchor before the engine appends them.
func (e *Engine) SetTELCommit(f func(drivers.TELCommit) error) {
	e.commitMu.Lock()
	e.telCommit = f
	e.commitMu.Unlock()
}

// commit offers a registry event and its anchor for keeping. With nothing
// installed there is nothing to offer them to.
func (e *Engine) commit(id *identity, sn uint64, kel, tel []byte) (string, error) {
	sig, err := e.signed(id, kel)
	if err != nil {
		return "", err
	}
	e.commitMu.Lock()
	f := e.telCommit
	e.commitMu.Unlock()
	if f == nil {
		return sig, nil
	}
	return sig, f(drivers.TELCommit{AID: id.AID, SN: int(sn), KELRaw: kel, TELRaw: tel, Signature: sig})
}

// extend appends raw to id's key log: the one place an event other than a
// rotation joins a key log, and it does so only with a signature by id's
// current key over exactly raw, checked here whatever the caller checked.
// also runs, under the same lock, for what else the event changes.
func (e *Engine) extend(id *identity, raw []byte, sig string, also func()) error {
	e.state.mu.RLock()
	key := id.PublicKey
	e.state.mu.RUnlock()
	if err := verifiedBy(id.AID, key, raw, sig); err != nil {
		return err
	}
	return e.appendEvent(id, raw, also)
}

// extendByRotation appends a rotation to id's key log. A rotation is signed
// by its new keys, which the callers of this engine do not yet hand it, so
// it is the one event appended without a signature checked here.
func (e *Engine) extendByRotation(id *identity, raw []byte, also func()) error {
	return e.appendEvent(id, raw, also)
}

func (e *Engine) appendEvent(id *identity, raw []byte, also func()) error {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return err
	}
	next, err := entry(raw)
	if err != nil {
		return err
	}
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	if also != nil {
		also()
	}
	id.SN = int(ev.SN)
	id.LastSAID = ev.SAID
	id.KEL = append(id.KEL, next)
	return nil
}

// verifiedBy checks sig is aid's current key's signature over raw.
func verifiedBy(aid, key string, raw []byte, sig string) error {
	if key == "" {
		return fmt.Errorf("the key in force for %s is not known here (its log was restored without the "+
			"bytes it was published as, and no key was given with it), so nothing is appended to it", aid)
	}
	sigRaw, err := iacrypto.DecodeEd25519SignatureQB64(sig)
	if err != nil {
		return fmt.Errorf("the signature over an event of %s is unreadable, so it is not appended: %w", aid, err)
	}
	if err := keri.VerifySignature(key, raw, sigRaw); err != nil {
		return fmt.Errorf("an event of %s not signed by its current key is not appended: %w", aid, err)
	}
	return nil
}

// holdForWriting returns the identity named and holds it against every other
// event built on its log until the returned function is called. The identity
// is read again once held, because a reload may have replaced it meanwhile.
func (e *Engine) holdForWriting(name string) (*identity, func(), error) {
	id, err := e.state.get(name)
	if err != nil {
		return nil, nil, err
	}
	m, _ := e.writing.LoadOrStore(id.AID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	if id, err = e.state.get(name); err != nil {
		mu.Unlock()
		return nil, nil, err
	}
	return id, mu.Unlock, nil
}

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
	// An event seal naming the owner's inception event.
	//
	// Every identity here is self-addressing, so the identifier IS the digest of
	// its inception — which is what lets the seal name that event using only the
	// identifier, and what makes it resolvable by someone who has the owner's
	// log and nothing else.
	//
	// This was {"i": <owner>, "r": "owner"} until it was measured against an
	// independent implementation, which could not PARSE an inception carrying
	// it. Not "failed to validate" — the event was unreadable, so an owned
	// identity's entire log was unreadable to anything that did not already
	// share our private convention. KERI defines a closed set of seal shapes and
	// that was not one of them.
	//
	// The role label is gone; position replaces it. An owner seal is an event
	// seal in an establishment event — see the reader in the server package for
	// why that is unambiguous and what would break it.
	if !strings.HasPrefix(ownerAID, "E") {
		return nil, fmt.Errorf("%q is not a self-addressing identifier, so an owner seal "+
			"naming it would point at no event", ownerAID)
	}
	anchor := json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`, ownerAID, ownerAID))
	return e.incept(publicKey, nextPublicKey, name, []json.RawMessage{anchor})
}

// Incept founds an identity, optionally designating witnesses for it.
func (e *Engine) Incept(req drivers.InceptionRequest) (*drivers.DriverInceptionResponse, error) {
	var anchors []json.RawMessage
	if req.OwnerAID != "" {
		if !strings.HasPrefix(req.OwnerAID, "E") {
			return nil, fmt.Errorf("%q is not a self-addressing identifier, so an owner seal "+
				"naming it would point at no event", req.OwnerAID)
		}
		anchors = append(anchors, json.RawMessage(
			fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`, req.OwnerAID, req.OwnerAID)))
	}
	// Anything else the caller anchors — the messaging keys an identity commits
	// to, most importantly. Dropping these silently would leave an identity
	// whose identifier promises nothing about the keys people encrypt to it
	// with, which is the whole reason they are anchored rather than served.
	for i, a := range req.AnchorData {
		raw, err := normaliseAnchor(a)
		if err != nil {
			return nil, fmt.Errorf("anchor %d: %w", i, err)
		}
		anchors = append(anchors, raw)
	}
	return e.inceptWith(req.PublicKey, req.NextPublicKey, req.Name, anchors, req.Witnesses, req.Toad,
		req.NextKeyDigests, req.NextThreshold)
}

func (e *Engine) incept(publicKey, nextPublicKey, name string, data []json.RawMessage) (*drivers.DriverInceptionResponse, error) {
	return e.inceptWith(publicKey, nextPublicKey, name, data, nil, 0, nil, "")
}

// inceptionOver builds the inception event of these keys: the one construction
// every inception this engine makes uses, so an identity made from derived keys
// can be built again from the keys alone (InceptionOf).
func inceptionOver(publicKey, nextPublicKey string, data []json.RawMessage, witnesses []string, toad int, nextDigests []string, nextThreshold string) (pub, nextDigest string, raw []byte, err error) {
	pub, err = normaliseKey(publicKey, true)
	if err != nil {
		return "", "", nil, fmt.Errorf("the signing key: %w", err)
	}
	nextPub, err := normaliseKey(nextPublicKey, true)
	if err != nil {
		return "", "", nil, fmt.Errorf("the next signing key: %w", err)
	}
	if pub == nextPub {
		return "", "", nil, fmt.Errorf("the next key is the same as the current one; pre-rotation " +
			"would commit to the key already in use, so a compromise of it would also " +
			"carry the right to rotate")
	}
	// The commitment is a digest of the next key's qb64 TEXT, not of its raw
	// bytes and not the key itself. Committing to anything else produces a
	// rotation that every conformant implementation refuses, at the point where
	// the identity most needs to rotate.
	nextDigest, err = iacrypto.NextKeyDigest(nextPub)
	if err != nil {
		return "", "", nil, fmt.Errorf("committing to the next key: %w", err)
	}

	// A witness a caller cannot name properly is refused rather than written
	// in. An inception event is permanent, so an unverifiable observer in it is
	// a mistake with no way back.
	for i, w := range witnesses {
		if len(w) != 44 || w[0] != 'B' {
			return "", "", nil, fmt.Errorf("witness %d is %q, which is not a non-transferable "+
				"identifier; its receipts could not be checked without resolving a key log", i, w)
		}
	}
	// A caller may commit to more than one next key — a post-quantum key
	// alongside the classical one, most importantly. Dropping these silently
	// would leave the identity committed to a single classical successor while
	// everything upstream believed otherwise, and nothing would notice until a
	// rotation that could not be performed.
	committed := []string{nextDigest}
	if len(nextDigests) > 0 {
		committed = nextDigests
	}
	in := keri.InceptionInput{
		Keys:        []string{pub},
		NextDigests: committed,
		Data:        data,
		Witnesses:   witnesses,
		// Self-addressing: the identifier is a digest over the whole inception
		// event, so it commits to the witnesses and thresholds as well as the
		// key. A basic identifier is only the key, and an identity created that
		// way could not be reproduced from its own event.
		Derivation: "self-addressing",
	}
	// A stated threshold is passed through; otherwise the builder derives the
	// default, and writing a guess at that default would be writing the
	// caller's arithmetic rather than the protocol's.
	if toad > 0 {
		in.Toad = &toad
	}
	// Stated only when the caller states it, for the same reason as the witness
	// threshold: writing a guess at the builder's default is writing our
	// arithmetic rather than the protocol's.
	if nextThreshold != "" {
		in.Nsith = json.RawMessage(strconv.Quote(nextThreshold))
	}
	raw, err = keri.BuildInception(in)
	if err != nil {
		return "", "", nil, fmt.Errorf("building the inception event: %w", err)
	}
	return pub, nextDigest, raw, nil
}

// InceptionOf is the inception event of these keys with no witnesses and
// nothing anchored, exactly as CreateInceptionNamed makes it, so the key log of
// an identity made that way can be shown again from its keys after the engine
// that made it has stopped holding it.
func InceptionOf(publicKey, nextPublicKey string) ([]byte, error) {
	_, _, raw, err := inceptionOver(publicKey, nextPublicKey, nil, nil, 0, nil, "")
	return raw, err
}

func (e *Engine) inceptWith(publicKey, nextPublicKey, name string, data []json.RawMessage, witnesses []string, toad int, nextDigests []string, nextThreshold string) (*drivers.DriverInceptionResponse, error) {
	pub, nextDigest, raw, err := inceptionOver(publicKey, nextPublicKey, data, witnesses, toad, nextDigests, nextThreshold)
	if err != nil {
		return nil, err
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
	return e.CreateDelegatedInceptionKept(publicKey, nextPublicKey, name, delegatorName, nil, 0, nil)
}

// WitnessConfig is the witnesses an identity names now and how many must
// receipt each of its events.
func (e *Engine) WitnessConfig(name string) ([]string, int, error) {
	id, err := e.state.get(name)
	if err != nil {
		return nil, 0, err
	}
	e.state.mu.RLock()
	defer e.state.mu.RUnlock()
	return append([]string(nil), id.Witnesses...), id.Toad, nil
}

// CreateDelegatedInceptionKept is CreateDelegatedInception, offering the
// delegator's approval and the new inception to keep before either is held. A
// keep that fails leaves both logs as they were.
//
// witnesses and toad, when witnesses is not empty, are written into the
// delegated inception: the witnesses it names and how many must receipt each of
// its events.
func (e *Engine) CreateDelegatedInceptionKept(publicKey, nextPublicKey, name, delegatorName string, witnesses []string, toad int, keep func(drivers.KELKeep) error) (*drivers.DriverDelegatedInceptionResponse, error) {
	delegator, release, err := e.holdForWriting(delegatorName)
	if err != nil {
		return nil, fmt.Errorf("the delegator: %w", err)
	}
	defer release()
	pub, nextDigest, dip, dipEvent, err := delegatedInceptionOver(publicKey, nextPublicKey, delegator.AID, witnesses, toad)
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

	approvalSig, err := e.signed(delegator, ixn)
	if err != nil {
		return nil, err
	}
	if keep != nil {
		// The name must be free before anything is kept, or the store would
		// hold a delegation the engine then refuses to.
		heldAs := name
		if heldAs == "" {
			heldAs = dipEvent.Identifier
		}
		if held, err := e.state.get(heldAs); err == nil && held.AID != dipEvent.Identifier {
			return nil, fmt.Errorf("the name %q already holds %s", heldAs, held.AID)
		}
		if err := keep(drivers.KELKeep{AID: delegator.AID, SN: int(ixnEvent.SN), Raw: ixn, Delegated: dip, Signature: approvalSig}); err != nil {
			return nil, fmt.Errorf("the delegation was not kept, so it was not made: %w", err)
		}
	}
	if err := e.holdDelegatedIdentity(name, pub, nextDigest, dip, dipEvent); err != nil {
		return nil, err
	}
	// The delegator's log only advances once its approval is recorded.
	if err := e.extend(delegator, ixn, approvalSig, nil); err != nil {
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

// ReinstateDelegatedIdentity holds a delegated identity again, after a restart,
// without approving it a second time.
//
// The engine's state is in memory, so a delegated identity whose keys are
// derived rather than stored is rebuilt by producing its inception again — the
// same keys give the same event and the same identifier. What must NOT be
// produced again is the delegator's approval. Founding it anew appended a second
// anchoring event to the delegator's log in memory only, so the log the engine
// served ran ahead of the one on disk, and the two disagreed from then on.
//
// So the approval is looked for instead: the delegator's log, as reloaded, must
// already carry a seal naming exactly this inception. If it does not, nothing
// ever approved this identity and it is refused rather than reinstated.
func (e *Engine) ReinstateDelegatedIdentity(publicKey, nextPublicKey, name, delegatorName string) (*drivers.DriverDelegatedInceptionResponse, error) {
	delegator, err := e.state.get(delegatorName)
	if err != nil {
		return nil, fmt.Errorf("the delegator: %w", err)
	}
	pub, nextDigest, dip, dipEvent, err := delegatedInceptionOver(publicKey, nextPublicKey, delegator.AID, nil, 0)
	if err != nil {
		return nil, err
	}
	approval, approvalRaw, ok := e.approvalIn(delegator, dipEvent.Identifier, fmt.Sprintf("%x", dipEvent.SN), dipEvent.SAID)
	if !ok {
		return nil, fmt.Errorf("the delegator's log carries no approval of %s, so it was never "+
			"delegated and cannot be reinstated", dipEvent.Identifier)
	}
	if err := e.holdDelegatedIdentity(name, pub, nextDigest, dip, dipEvent); err != nil {
		return nil, err
	}
	dipBody, err := eventMap(dip)
	if err != nil {
		return nil, err
	}
	return &drivers.DriverDelegatedInceptionResponse{
		AID:          dipEvent.Identifier,
		DelegatorAID: delegator.AID,
		Said:         dipEvent.SAID,
		DipEvent:     dipBody,
		DelegatorIxn: approval,
		RawBytesB64:  b64(dip),

		DelegatorIxnRawBytesB64: approvalRaw,
		PublicKey:               pub,
		NextKeyDigest:           nextDigest,
	}, nil
}

// delegatedInceptionOver builds the inception of an identity delegated by the
// given identifier, over the given keys.
// DelegatedInceptionOf is the identifier and digest the delegated inception
// of these keys by delegator, naming these witnesses, would have: the same
// construction CreateDelegatedInceptionKept uses, so an identity made from
// derived keys can be recognised later from the keys alone.
func DelegatedInceptionOf(publicKey, nextPublicKey, delegatorAID string, witnesses []string, toad int) (aid, said string, err error) {
	_, _, _, ev, err := delegatedInceptionOver(publicKey, nextPublicKey, delegatorAID, witnesses, toad)
	if err != nil {
		return "", "", err
	}
	return ev.Identifier, ev.SAID, nil
}

// witnesses and toad, when witnesses is not empty, are the witnesses the
// delegated identity names and how many must receipt each of its events.
func delegatedInceptionOver(publicKey, nextPublicKey, delegatorAID string, witnesses []string, toad int) (
	pub, nextDigest string, dip []byte, dipEvent *keri.Event, err error,
) {
	pub, err = normaliseKey(publicKey, true)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("the signing key: %w", err)
	}
	nextPub, err := normaliseKey(nextPublicKey, true)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("the next signing key: %w", err)
	}
	nextDigest, err = iacrypto.NextKeyDigest(nextPub)
	if err != nil {
		return "", "", nil, nil, err
	}
	in := keri.DelegationInput{
		Keys:        []string{pub},
		NextDigests: []string{nextDigest},
		Delegator:   delegatorAID,
	}
	if len(witnesses) > 0 {
		in.Witnesses = witnesses
		in.Toad = &toad
	}
	dip, err = keri.BuildDelegatedInception(in)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("building the delegated inception: %w", err)
	}
	dipEvent, err = keri.ParseEvent(dip)
	if err != nil {
		return "", "", nil, nil, err
	}
	return pub, nextDigest, dip, dipEvent, nil
}

func (e *Engine) holdDelegatedIdentity(name, pub, nextDigest string, dip []byte, dipEvent *keri.Event) error {
	if name == "" {
		name = dipEvent.Identifier
	}
	first, err := entry(dip)
	if err != nil {
		return err
	}
	return e.state.claim(&identity{
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
}

// approvalIn finds the event in the delegator's log whose seals name exactly
// this identifier, sequence number and digest.
func (e *Engine) approvalIn(delegator *identity, aid, sn, said string) (map[string]interface{}, string, bool) {
	e.state.mu.RLock()
	defer e.state.mu.RUnlock()
	for _, ev := range delegator.KEL {
		seals, _ := ev.Parsed["a"].([]interface{})
		for _, raw := range seals {
			seal, _ := raw.(map[string]interface{})
			if seal["i"] == aid && seal["s"] == sn && seal["d"] == said {
				rawB64 := ""
				if len(ev.Raw) > 0 {
					rawB64 = b64(ev.Raw)
				}
				return ev.Parsed, rawB64, true
			}
		}
	}
	return nil, "", false
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
	return e.Rotate(drivers.RotationRequest{
		Name: name, NewPublicKey: newPublicKey, NewNextPublicKey: newNextPublicKey,
		AnchorData: anchorData,
	})
}

// Rotate rotates the keys and, where asked, amends who witnesses the identity.
func (e *Engine) Rotate(req drivers.RotationRequest) (*drivers.DriverRotationResponse, error) {
	name, newPublicKey, newNextPublicKey, anchorData :=
		req.Name, req.NewPublicKey, req.NewNextPublicKey, req.AnchorData
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
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
	newNextDigest, err := iacrypto.NextKeyDigest(newNextPub)
	if err != nil {
		return nil, err
	}

	anchors, err := rawData(anchorData)
	if err != nil {
		return nil, err
	}
	// A witness being added must be nameable, for the same reason it must be at
	// inception: what the event carries is the key its receipts verify against.
	for i, w := range req.AddWitnesses {
		if len(w) != 44 || w[0] != 'B' {
			return nil, fmt.Errorf("witness %d being added is %q, which is not a "+
				"non-transferable identifier; its receipts could not be checked", i, w)
		}
	}
	rotIn := keri.RotationInput{
		Prefix:         id.AID,
		Keys:           []string{newPub},
		PriorSAID:      id.LastSAID,
		SN:             id.SN + 1,
		NextDigests:    []string{newNextDigest},
		PriorWitnesses: id.Witnesses,
		Cuts:           req.CutWitnesses,
		Adds:           req.AddWitnesses,
		Data:           anchors,
	}
	if req.Toad > 0 {
		rotIn.Toad = &req.Toad
	}
	raw, err := keri.BuildRotation(rotIn)
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

	if err := e.extendByRotation(id, raw, func() {
		id.PublicKey = newPub
		id.NextKeyDigest = newNextDigest
		// The witness set now in force, read back off the event rather than
		// recomputed here. The event is what everyone else will read, so
		// anything this engine believes that the event does not say is wrong.
		id.Witnesses = witnessesAfter(id.Witnesses, ev)
		id.Toad = witnessThreshold(ev)
	}); err != nil {
		return nil, err
	}

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
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
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
	// The first key must be the one the previous event committed to, as a
	// single-key rotation's must, since it is the key this engine holds in
	// force afterwards; the keys of owners joining follow it.
	e.state.mu.RLock()
	committed := id.NextKeyDigest
	e.state.mu.RUnlock()
	if d, err := keri.NextDigest(normalised[0]); err != nil || d != committed {
		return nil, fmt.Errorf("the multisig rotation's first key is not the one the identity committed to (%s)", committed)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	body, err := eventMap(raw)
	if err != nil {
		return nil, err
	}

	if err := e.extendByRotation(id, raw, func() {
		id.PublicKey = normalised[0]
		id.NextKeyDigest = nextKeyDigests[0]
	}); err != nil {
		return nil, err
	}

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
	return e.InteractKept(name, data, nil)
}

// InteractKept is Interact, offering the event to keep before it is appended.
// A keep that fails leaves the log as it was.
func (e *Engine) InteractKept(name string, data []interface{}, keep func(drivers.KELKeep) error) (*drivers.DriverInteractResponse, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
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

	sig, err := e.signed(id, raw)
	if err != nil {
		return nil, err
	}
	if keep != nil {
		if err := keep(drivers.KELKeep{AID: id.AID, SN: int(ev.SN), Raw: raw, Signature: sig}); err != nil {
			return nil, fmt.Errorf("the interaction was not kept, so it was not made: %w", err)
		}
	}
	if err := e.extend(id, raw, sig, nil); err != nil {
		return nil, err
	}

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
	return e.kelOf(id), nil
}

// GetKelByAID returns the key log of the identity held with this identifier,
// whatever name it is held under. Read only: an identity the engine does not
// hold is an error, never a reason to make one.
func (e *Engine) GetKelByAID(aid string) (*drivers.DriverKelResponse, error) {
	e.state.mu.RLock()
	var found *identity
	for _, id := range e.state.identities {
		if id.AID != aid {
			continue
		}
		if found != nil && found != id {
			e.state.mu.RUnlock()
			return nil, fmt.Errorf("%s is held twice, under %q and %q", aid, found.Name, id.Name)
		}
		found = id
	}
	e.state.mu.RUnlock()
	if found == nil {
		return nil, fmt.Errorf("no identity %s is held", aid)
	}
	return e.kelOf(found), nil
}

func (e *Engine) kelOf(id *identity) *drivers.DriverKelResponse {
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
	}
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
			raw, err := iacrypto.DecodeBase64(req.RawEventsB64[i])
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
	keyInForce := ""
	if last := entries[len(entries)-1]; last.Raw != nil {
		ev, err := keri.ParseEvent(last.Raw)
		if err != nil {
			return nil, err
		}
		sn, lastSAID = int(ev.SN), ev.SAID
	}
	// The witnesses in force are what the establishment events say, read in
	// order: an inception names them, a rotation amends them. An interaction
	// names none, so reading them off the last event alone forgot an
	// identity's witnesses whenever its last event was an interaction.
	for _, e := range entries {
		if e.Raw == nil {
			continue
		}
		ev, err := keri.ParseEvent(e.Raw)
		if err != nil {
			return nil, err
		}
		switch ev.Ilk {
		case "icp", "dip":
			witnesses, toad = ev.Witnesses, witnessThreshold(ev)
		case "rot", "drt":
			witnesses, toad = witnessesAfter(witnesses, ev), witnessThreshold(ev)
		}
		// The key in force is the one the last establishment event names,
		// whatever the caller says: every event appended from here must be
		// signed by it.
		if (ev.Ilk == "icp" || ev.Ilk == "dip" || ev.Ilk == "rot" || ev.Ilk == "drt") && len(ev.Keys) > 0 {
			keyInForce = ev.Keys[0]
		}
	}

	if lastSAID == "" {
		return nil, fmt.Errorf("reloading %s needs the digest of its most recent event; "+
			"without it the next event cannot name its predecessor", req.AID)
	}

	// Taken from the log only where the whole log was checked; a log handed
	// over without the bytes it was published as says nothing reliable about
	// its keys, and the key the caller holds for it is used instead.
	pub := req.PublicKey
	if complete && keyInForce != "" {
		pub = keyInForce
	}
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

// witnessesAfter applies a rotation's cuts and adds to the set that preceded it.
//
// Taken from the event rather than from the request, so that what this engine
// believes about an identity cannot drift from what the identity has published.
// A rotation that says nothing about witnesses leaves the set alone.
func witnessesAfter(prior []string, ev *keri.Event) []string {
	if ev == nil || (len(ev.WitnessCut) == 0 && len(ev.WitnessAdd) == 0) {
		return prior
	}
	cut := map[string]bool{}
	for _, w := range ev.WitnessCut {
		cut[w] = true
	}
	out := make([]string, 0, len(prior)+len(ev.WitnessAdd))
	for _, w := range prior {
		if !cut[w] {
			out = append(out, w)
		}
	}
	for _, w := range ev.WitnessAdd {
		out = append(out, w)
	}
	return out
}
