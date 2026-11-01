package keriengine

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

// FormatCredential builds a credential without issuing it.
//
// Stateless — nothing is anchored and no log moves. This is what a caller uses
// to obtain a credential's identifier before deciding to issue it.
func (e *Engine) FormatCredential(claims map[string]interface{}, schemaSaid, issuerAid string) (*drivers.DriverFormatCredentialResponse, error) {
	if schemaSaid == "" {
		return nil, fmt.Errorf("a credential needs the identifier of the schema it claims to " +
			"satisfy; without one nothing can check whether it does")
	}
	if issuerAid == "" {
		return nil, fmt.Errorf("a credential needs an issuer")
	}
	data, err := stampedClaims(claims)
	if err != nil {
		return nil, err
	}
	raw, err := keri.BuildCredential(keri.CredentialInput{
		SchemaSAID: schemaSaid,
		Issuer:     issuerAid,
		Data:       data,
	})
	if err != nil {
		return nil, fmt.Errorf("building the credential: %w", err)
	}
	s, err := said(raw)
	if err != nil {
		return nil, err
	}
	return &drivers.DriverFormatCredentialResponse{
		RawBytesB64: b64(raw),
		Said:        s,
		Size:        len(raw),
	}, nil
}

// InceptRegistry creates a credential registry and anchors it in the issuer's
// key log.
//
// Both events are produced together. A registry whose creation is not anchored
// is a registry nothing vouches for: a verifier has no way to tell it from one
// invented after the fact to backdate an issuance.
func (e *Engine) InceptRegistry(name string) (*drivers.DriverRegistryInceptResponse, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	p, err := e.prepareRegistry(id)
	if err != nil {
		return nil, err
	}
	return e.appendPreparedRegistry(id, p)
}

// PrepareRegistryInception builds a registry's inception and the interaction
// that anchors it, on the key log as it stands now, without appending them.
func (e *Engine) PrepareRegistryInception(name string) (*drivers.PreparedRegistry, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	return e.prepareRegistry(id)
}

// AppendPreparedRegistry appends a registry's inception exactly as it was
// prepared, while its interaction still extends the key log's tip.
func (e *Engine) AppendPreparedRegistry(name string, p *drivers.PreparedRegistry) (*drivers.DriverRegistryInceptResponse, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	return e.appendPreparedRegistry(id, p)
}

func (e *Engine) prepareRegistry(id *identity) (*drivers.PreparedRegistry, error) {
	// A registry needs a nonce, or two registries founded by the same issuer
	// would have the same identifier — and an issuance into one would read as
	// an issuance into the other.
	nonce, err := registryNonce()
	if err != nil {
		return nil, err
	}
	vcp, err := keri.BuildRegistryInception(keri.RegistryInput{Issuer: id.AID, Nonce: nonce})
	if err != nil {
		return nil, fmt.Errorf("building the registry: %w", err)
	}
	vcpEvent, err := keri.VerifyTELEvent(vcp)
	if err != nil {
		return nil, fmt.Errorf("the registry event this engine built does not verify: %w", err)
	}
	vcpBody, err := eventMap(vcp)
	if err != nil {
		return nil, err
	}
	registrySAID, _ := vcpBody["i"].(string)
	if registrySAID == "" {
		registrySAID = vcpEvent.SAID
	}
	seal, err := eventSeal(registrySAID, "0", vcpEvent.SAID)
	if err != nil {
		return nil, err
	}
	e.state.mu.RLock()
	prior, sn := id.LastSAID, id.SN+1
	e.state.mu.RUnlock()
	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    id.AID,
		PriorSAID: prior,
		SN:        sn,
		Data:      []json.RawMessage{seal},
	})
	if err != nil {
		return nil, fmt.Errorf("anchoring the registry: %w", err)
	}
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, err
	}
	return &drivers.PreparedRegistry{Issuer: id.AID, Registry: registrySAID, VcpRaw: vcp, VcpSAID: vcpEvent.SAID,
		IxnRaw: ixn, IxnSAID: ixnEvent.SAID, SN: int(ixnEvent.SN), Prior: prior}, nil
}

func (e *Engine) appendPreparedRegistry(id *identity, p *drivers.PreparedRegistry) (*drivers.DriverRegistryInceptResponse, error) {
	if p == nil || p.Issuer != id.AID {
		return nil, fmt.Errorf("the prepared registry is not this identity's")
	}
	e.state.mu.RLock()
	tipSAID, tipSN := id.LastSAID, id.SN
	e.state.mu.RUnlock()
	if p.Prior != tipSAID || p.SN != tipSN+1 {
		return nil, drivers.ErrStalePreparation
	}
	vcpEvent, err := keri.VerifyTELEvent(p.VcpRaw)
	if err != nil || vcpEvent.SAID != p.VcpSAID {
		return nil, fmt.Errorf("the prepared registry inception does not verify")
	}
	vcpBody, err := eventMap(p.VcpRaw)
	if err != nil {
		return nil, err
	}
	registrySAID, _ := vcpBody["i"].(string)
	if registrySAID == "" {
		registrySAID = vcpEvent.SAID
	}
	if registrySAID != p.Registry {
		return nil, fmt.Errorf("the prepared registry inception is of another registry")
	}
	seal, err := eventSeal(registrySAID, "0", vcpEvent.SAID)
	if err != nil {
		return nil, err
	}
	want, err := keri.BuildInteraction(keri.InteractionInput{Prefix: id.AID, PriorSAID: p.Prior, SN: p.SN, Data: []json.RawMessage{seal}})
	if err != nil || string(want) != string(p.IxnRaw) {
		return nil, fmt.Errorf("the prepared interaction does not anchor the prepared registry")
	}
	vcp, ixn := p.VcpRaw, p.IxnRaw
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, err
	}
	ixnBody, err := eventMap(ixn)
	if err != nil {
		return nil, err
	}
	sig, kept, err := e.commit(id, ixnEvent.SN, ixn, vcp)
	if err != nil {
		return nil, err
	}
	if err := e.extend(id, ixn, sig, kept, func() {
		if id.Registries == nil {
			id.Registries = map[string]*registry{}
		}
		id.Registries[registrySAID] = &registry{
			SAID:         registrySAID,
			TEL:          map[string][][]byte{},
			IssuanceSAID: map[string]string{},
		}
	}); err != nil {
		return nil, err
	}

	return &drivers.DriverRegistryInceptResponse{
		RegistrySaid:   registrySAID,
		VcpSaid:        vcpEvent.SAID,
		VcpEvent:       vcpBody,
		VcpJsonB64:     b64(vcp),
		IxnSaid:        ixnEvent.SAID,
		IxnEvent:       ixnBody,
		SequenceNumber: int(ixnEvent.SN),
		IxnRawBytesB64: b64(ixn),
	}, nil
}

// IssueCredential issues a credential without a registry.
//
// A credential issued outside a registry can be verified but never revoked:
// revocation is an event in a registry's transaction log, and there is no log
// to write it to. Callers that may need to revoke should use
// IssueCredentialInRegistry.
func (e *Engine) IssueCredential(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}) (*drivers.DriverIssueCredentialResponse, error) {
	return e.issue(name, claims, schemaSaid, holderAid, edges, "")
}

// IssueCredentialInRegistry issues a credential into a registry, so it can
// later be revoked.
func (e *Engine) IssueCredentialInRegistry(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*drivers.DriverIssueCredentialResponse, error) {
	if registrySaid == "" {
		return nil, fmt.Errorf("no registry was named; issue without one through IssueCredential, " +
			"which is explicit that the credential cannot be revoked")
	}
	return e.issue(name, claims, schemaSaid, holderAid, edges, registrySaid)
}

func (e *Engine) issue(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*drivers.DriverIssueCredentialResponse, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	p, err := e.prepare(id, claims, schemaSaid, holderAid, edges, registrySaid)
	if err != nil {
		return nil, err
	}
	return e.appendPrepared(id, p)
}

// PrepareCredentialInRegistry builds an issuance into a registry without
// appending it: the credential, its issuance event, and the interaction that
// anchors it, on the key log as it stands now.
func (e *Engine) PrepareCredentialInRegistry(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*drivers.PreparedIssuance, error) {
	if registrySaid == "" {
		return nil, fmt.Errorf("a prepared issuance is into a registry")
	}
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	return e.prepare(id, claims, schemaSaid, holderAid, edges, registrySaid)
}

// AppendPreparedIssuance appends an issuance exactly as it was prepared, while
// its interaction still extends the key log's tip.
func (e *Engine) AppendPreparedIssuance(name string, p *drivers.PreparedIssuance) (*drivers.DriverIssueCredentialResponse, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	return e.appendPrepared(id, p)
}

func (e *Engine) prepare(id *identity, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*drivers.PreparedIssuance, error) {
	if schemaSaid == "" {
		return nil, fmt.Errorf("a credential needs the identifier of the schema it satisfies")
	}
	data, err := stampedClaims(claims)
	if err != nil {
		return nil, err
	}
	in := keri.CredentialInput{
		SchemaSAID: schemaSaid,
		Issuer:     id.AID,
		Recipient:  holderAid,
		Registry:   registrySaid,
		Data:       data,
	}
	if len(edges) > 0 {
		// Edges name the credentials this one depends on. They are part of the
		// credential's own digest, so a credential cannot have its chain
		// altered after issue without becoming a different credential.
		src, err := json.Marshal(edges)
		if err != nil {
			return nil, fmt.Errorf("the credential's edges cannot be encoded: %w", err)
		}
		in.Source = src
	}
	acdc, err := keri.BuildCredential(in)
	if err != nil {
		return nil, fmt.Errorf("building the credential: %w", err)
	}
	cred, err := keri.VerifyCredential(acdc)
	if err != nil {
		return nil, fmt.Errorf("the credential this engine built does not verify: %w", err)
	}
	// What gets anchored depends on whether there is a registry. With one, the
	// issuance event is anchored and the credential's status is readable from
	// the registry. Without one, the credential itself is anchored, which
	// records that it was issued and leaves no place to record that it was not
	// revoked.
	p := &drivers.PreparedIssuance{Issuer: id.AID, Registry: registrySaid, AcdcRaw: acdc, AcdcSAID: cred.SAID}
	if registrySaid != "" {
		issRaw, err := keri.BuildIssuance(keri.IssuanceInput{
			CredentialSAID: cred.SAID,
			Registry:       registrySaid,
			DT:             time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00"),
		})
		if err != nil {
			return nil, fmt.Errorf("building the issuance event: %w", err)
		}
		issEvent, err := keri.VerifyTELEvent(issRaw)
		if err != nil {
			return nil, fmt.Errorf("the issuance event does not verify: %w", err)
		}
		p.IssRaw, p.IssSAID = issRaw, issEvent.SAID
	}
	seal, err := eventSeal(cred.SAID, "0", firstNonEmpty(p.IssSAID, cred.SAID))
	if err != nil {
		return nil, err
	}
	e.state.mu.RLock()
	prior, sn := id.LastSAID, id.SN+1
	e.state.mu.RUnlock()
	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    id.AID,
		PriorSAID: prior,
		SN:        sn,
		Data:      []json.RawMessage{seal},
	})
	if err != nil {
		return nil, fmt.Errorf("anchoring the issuance: %w", err)
	}
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, err
	}
	p.IxnRaw, p.IxnSAID, p.SN, p.Prior = ixn, ixnEvent.SAID, int(ixnEvent.SN), prior
	return p, nil
}

// appendPrepared appends a prepared issuance, checked to be what it says and
// to extend the tip. The caller holds id for writing.
func (e *Engine) appendPrepared(id *identity, p *drivers.PreparedIssuance) (*drivers.DriverIssueCredentialResponse, error) {
	if p == nil || p.Issuer != id.AID {
		return nil, fmt.Errorf("the prepared issuance is not this identity's")
	}
	e.state.mu.RLock()
	tipSAID, tipSN := id.LastSAID, id.SN
	e.state.mu.RUnlock()
	if p.Prior != tipSAID || p.SN != tipSN+1 {
		return nil, drivers.ErrStalePreparation
	}
	cred, err := keri.VerifyCredential(p.AcdcRaw)
	if err != nil || cred.SAID != p.AcdcSAID {
		return nil, fmt.Errorf("the prepared credential does not verify")
	}
	ixnEvent, err := keri.ParseEvent(p.IxnRaw)
	if err != nil || ixnEvent.SAID != p.IxnSAID || int(ixnEvent.SN) != p.SN {
		return nil, fmt.Errorf("the prepared interaction is not what was prepared")
	}
	// The interaction must anchor exactly this issuance, or the pair would be
	// appended as proof of each other when it is not.
	seal, err := eventSeal(p.AcdcSAID, "0", firstNonEmpty(p.IssSAID, p.AcdcSAID))
	if err != nil {
		return nil, err
	}
	want, err := keri.BuildInteraction(keri.InteractionInput{Prefix: id.AID, PriorSAID: p.Prior, SN: p.SN, Data: []json.RawMessage{seal}})
	if err != nil || string(want) != string(p.IxnRaw) {
		return nil, fmt.Errorf("the prepared interaction does not anchor the prepared issuance")
	}
	var sig string
	var kept func(drivers.KELKeep) error
	if p.Registry != "" {
		issEvent, err := keri.VerifyTELEvent(p.IssRaw)
		if err != nil || issEvent.SAID != p.IssSAID || issEvent.Subject != p.AcdcSAID {
			return nil, fmt.Errorf("the prepared issuance event is not this credential's")
		}
		if sig, kept, err = e.commit(id, ixnEvent.SN, p.IxnRaw, p.IssRaw); err != nil {
			return nil, err
		}
	} else if sig, err = e.signed(id, p.IxnRaw); err != nil {
		return nil, err
	}
	acdcBody, err := eventMap(p.AcdcRaw)
	if err != nil {
		return nil, err
	}
	ixnBody, err := eventMap(p.IxnRaw)
	if err != nil {
		return nil, err
	}
	if err := e.extend(id, p.IxnRaw, sig, kept, func() {
		if p.Registry == "" {
			return
		}
		if id.Registries == nil {
			id.Registries = map[string]*registry{}
		}
		reg := id.Registries[p.Registry]
		if reg == nil {
			reg = &registry{SAID: p.Registry, TEL: map[string][][]byte{}, IssuanceSAID: map[string]string{}}
			id.Registries[p.Registry] = reg
		}
		reg.TEL[p.AcdcSAID] = append(reg.TEL[p.AcdcSAID], p.IssRaw)
		reg.IssuanceSAID[p.AcdcSAID] = p.IssSAID
	}); err != nil {
		return nil, err
	}

	return &drivers.DriverIssueCredentialResponse{
		AID:            id.AID,
		AcdcSaid:       p.AcdcSAID,
		AcdcJsonB64:    b64(p.AcdcRaw),
		AcdcBody:       acdcBody,
		IxnRawBytesB64: b64(p.IxnRaw),
		IxnSaid:        ixnEvent.SAID,
		IxnEvent:       ixnBody,
		SequenceNumber: int(ixnEvent.SN),
		IssSaid:        p.IssSAID,
		IssRawBytesB64: b64(p.IssRaw),
	}, nil
}

// RevokeCredential records that a credential is no longer valid.
func (e *Engine) RevokeCredential(name, acdcSaid, registrySaid, issSaid string) (*drivers.DriverRevokeCredentialResponse, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	p, err := e.prepareRevocation(id, acdcSaid, registrySaid, issSaid)
	if err != nil {
		return nil, err
	}
	return e.appendPreparedRevocation(id, p)
}

// PrepareRevocation builds a credential's revocation and the interaction that
// anchors it, without appending either.
func (e *Engine) PrepareRevocation(name, acdcSaid, registrySaid string) (*drivers.PreparedRevocation, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	return e.prepareRevocation(id, acdcSaid, registrySaid, "")
}

// AppendPreparedRevocation appends a revocation exactly as it was prepared,
// while its interaction still extends the key log's tip.
func (e *Engine) AppendPreparedRevocation(name string, p *drivers.PreparedRevocation) (*drivers.DriverRevokeCredentialResponse, error) {
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	return e.appendPreparedRevocation(id, p)
}

func (e *Engine) prepareRevocation(id *identity, acdcSaid, registrySaid, issSaid string) (*drivers.PreparedRevocation, error) {
	if acdcSaid == "" || registrySaid == "" {
		return nil, fmt.Errorf("revoking needs both the credential and the registry it was issued into")
	}
	// The revocation names the issuance as its predecessor, which is what makes
	// the transaction log a chain rather than a set of assertions. Without it a
	// revocation could be produced for a credential that was never issued.
	if issSaid == "" {
		e.state.mu.RLock()
		if reg := id.Registries[registrySaid]; reg != nil {
			issSaid = reg.IssuanceSAID[acdcSaid]
		}
		e.state.mu.RUnlock()
	}
	if issSaid == "" {
		return nil, fmt.Errorf("no issuance event is known for %s in registry %s; a revocation "+
			"has to name the issuance it revokes", acdcSaid, registrySaid)
	}
	e.state.mu.RLock()
	var tel [][]byte
	if reg := id.Registries[registrySaid]; reg != nil {
		tel = reg.TEL[acdcSaid]
	}
	e.state.mu.RUnlock()
	for _, raw := range tel {
		if ev, err := keri.VerifyTELEvent(raw); err == nil && ev.Ilk == "rev" {
			return nil, fmt.Errorf("%s is already revoked", acdcSaid)
		}
	}
	rev, err := keri.BuildRevocation(keri.RevocationInput{
		CredentialSAID: acdcSaid,
		Registry:       registrySaid,
		PriorISSSAID:   issSaid,
		DT:             time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00"),
	})
	if err != nil {
		return nil, fmt.Errorf("building the revocation: %w", err)
	}
	revEvent, err := keri.VerifyTELEvent(rev)
	if err != nil {
		return nil, fmt.Errorf("the revocation does not verify: %w", err)
	}
	seal, err := eventSeal(acdcSaid, "1", revEvent.SAID)
	if err != nil {
		return nil, err
	}
	e.state.mu.RLock()
	prior, sn := id.LastSAID, id.SN+1
	e.state.mu.RUnlock()
	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: id.AID, PriorSAID: prior, SN: sn, Data: []json.RawMessage{seal}})
	if err != nil {
		return nil, fmt.Errorf("anchoring the revocation: %w", err)
	}
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, err
	}
	return &drivers.PreparedRevocation{Issuer: id.AID, Registry: registrySaid, AcdcSAID: acdcSaid, IssSAID: issSaid,
		RevRaw: rev, RevSAID: revEvent.SAID, IxnRaw: ixn, IxnSAID: ixnEvent.SAID, SN: int(ixnEvent.SN), Prior: prior}, nil
}

// appendPreparedRevocation appends a prepared revocation, checked to be what
// it says and to extend the tip. The caller holds id for writing.
func (e *Engine) appendPreparedRevocation(id *identity, p *drivers.PreparedRevocation) (*drivers.DriverRevokeCredentialResponse, error) {
	if p == nil || p.Issuer != id.AID {
		return nil, fmt.Errorf("the prepared revocation is not this identity's")
	}
	e.state.mu.RLock()
	tipSAID, tipSN := id.LastSAID, id.SN
	e.state.mu.RUnlock()
	if p.Prior != tipSAID || p.SN != tipSN+1 {
		return nil, drivers.ErrStalePreparation
	}
	revEvent, err := keri.VerifyTELEvent(p.RevRaw)
	if err != nil || revEvent.SAID != p.RevSAID || revEvent.Subject != p.AcdcSAID {
		return nil, fmt.Errorf("the prepared revocation is not this credential's")
	}
	seal, err := eventSeal(p.AcdcSAID, "1", p.RevSAID)
	if err != nil {
		return nil, err
	}
	want, err := keri.BuildInteraction(keri.InteractionInput{Prefix: id.AID, PriorSAID: p.Prior, SN: p.SN, Data: []json.RawMessage{seal}})
	if err != nil || string(want) != string(p.IxnRaw) {
		return nil, fmt.Errorf("the prepared interaction does not anchor the prepared revocation")
	}
	ixnEvent, err := keri.ParseEvent(p.IxnRaw)
	if err != nil || ixnEvent.SAID != p.IxnSAID {
		return nil, fmt.Errorf("the prepared interaction is not what was prepared")
	}
	revBody, err := eventMap(p.RevRaw)
	if err != nil {
		return nil, err
	}
	ixnBody, err := eventMap(p.IxnRaw)
	if err != nil {
		return nil, err
	}
	sig, kept, err := e.commit(id, ixnEvent.SN, p.IxnRaw, p.RevRaw)
	if err != nil {
		return nil, err
	}
	if err := e.extend(id, p.IxnRaw, sig, kept, func() {
		if reg := id.Registries[p.Registry]; reg != nil {
			reg.TEL[p.AcdcSAID] = append(reg.TEL[p.AcdcSAID], p.RevRaw)
		}
	}); err != nil {
		return nil, err
	}
	return &drivers.DriverRevokeCredentialResponse{
		RevSaid:        p.RevSAID,
		RevEvent:       revBody,
		RevRawBytesB64: b64(p.RevRaw),
		IxnSaid:        ixnEvent.SAID,
		IxnEvent:       ixnBody,
		// The anchoring bytes, which this had a documented field for and did
		// not fill in. An anchor stored without them cannot have its signature
		// or its own digest checked against anything.
		IxnRawBytesB64: b64(p.IxnRaw),
		SequenceNumber: int(ixnEvent.SN),
	}, nil
}

// CredentialLog returns a credential's transaction log, in order, as the bytes
// each event was published as.
//
// This is what an issuer hands a verifier, and until now there was no way to
// get it: the events were recorded and nothing could read them back, so the
// question "has this been revoked?" had no answer anybody could supply. Raw
// bytes rather than parsed events, because the log chains by digest and a
// re-serialised event derives a different identifier and chains to nothing.
//
// A log with no revocation in it is not the same as no log. An empty result
// means this issuer has no record of the credential at all, which a verifier
// must not read as "still valid".
func (e *Engine) CredentialLog(name, registrySaid, acdcSaid string) ([]string, error) {
	if registrySaid == "" || acdcSaid == "" {
		return nil, fmt.Errorf("a transaction log is identified by both a registry and a credential")
	}
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	reg := id.Registries[registrySaid]
	if reg == nil {
		return nil, fmt.Errorf("%s knows no registry %s", name, registrySaid)
	}
	events := reg.TEL[acdcSaid]
	if len(events) == 0 {
		return nil, fmt.Errorf("registry %s holds no events for %s, so it can say nothing about "+
			"whether that credential is still valid", registrySaid, acdcSaid)
	}
	out := make([]string, 0, len(events))
	for _, raw := range events {
		out = append(out, b64(raw))
	}
	return out, nil
}

// VerifyCredential checks a credential and reports what it could establish.
//
// Each check is reported separately rather than collapsed into one verdict,
// because they are not equivalent: a credential can be structurally sound,
// issued by the identity it names, and still be revoked, or be for a schema the
// caller does not accept.
func (e *Engine) VerifyCredential(req *drivers.DriverVerifyCredentialRequest) (*drivers.DriverVerifyCredentialResponse, error) {
	if req == nil || req.AcdcJson == "" {
		return nil, fmt.Errorf("there is no credential to verify")
	}
	raw, err := iacrypto.DecodeBase64(req.AcdcJson)
	if err != nil {
		return nil, fmt.Errorf("the credential is not base64: %w", err)
	}

	out := &drivers.DriverVerifyCredentialResponse{Checks: map[string]interface{}{}}

	// The credential must be exactly the bytes its own identifier commits to.
	// Everything else is only meaningful once this holds.
	cred, err := keri.VerifyCredential(raw)
	if err != nil {
		out.Errors = append(out.Errors, fmt.Sprintf("the credential does not verify against its "+
			"own identifier, so it has been altered or was never well-formed: %v", err))
		out.Checks["structure"] = false
		return out, nil
	}
	out.Checks["structure"] = true
	out.AcdcSaid = cred.SAID

	if len(req.TrustedSchemaSaids) > 0 {
		accepted := false
		for _, s := range req.TrustedSchemaSaids {
			if s == cred.SchemaSAID {
				accepted = true
				break
			}
		}
		out.Checks["schema_accepted"] = accepted
		if !accepted {
			out.Errors = append(out.Errors, fmt.Sprintf("the credential is for schema %s, which is "+
				"not one this caller accepts", cred.SchemaSAID))
		}
	}

	if req.HolderAid != "" {
		matches := cred.Recipient == req.HolderAid
		out.Checks["holder"] = matches
		if !matches {
			out.Errors = append(out.Errors, fmt.Sprintf("the credential names %s as its subject, "+
				"not %s", cred.Recipient, req.HolderAid))
		}
	}

	// The issuer's key log establishes that the issuing identity is the one it
	// claims to be. Supplied parsed, so the same limit applies as in
	// ValidateKEL: the chain can be checked and the signatures cannot.
	if len(req.IssuerKelEvents) > 0 {
		kel, err := e.ValidateKEL(cred.Issuer, req.IssuerKelEvents)
		if err != nil {
			return nil, err
		}
		out.Checks["issuer_kel"] = kel.KelVerified
		if !kel.KelVerified {
			out.Errors = append(out.Errors, "the issuer's key log does not hold together: "+
				joinErrors(kel.ValidationErrors))
		}
	}

	// Whether the credential has since been withdrawn.
	//
	// A credential says nothing about its own revocation — revocation is an
	// event in the registry's transaction log — so a verifier that does not
	// read that log cannot tell a live credential from a withdrawn one. The
	// holder of a revoked credential is precisely the party with a reason not
	// to mention it, which is why this is checked rather than trusted.
	if len(req.RegistryEventsB64) > 0 {
		events := make([][]byte, 0, len(req.RegistryEventsB64))
		for i, b := range req.RegistryEventsB64 {
			raw, err := iacrypto.DecodeBase64(b)
			if err != nil {
				return nil, fmt.Errorf("transaction event %d is not base64: %w", i, err)
			}
			events = append(events, raw)
		}
		status, err := keri.CredentialStatus(cred.SAID, events)
		switch {
		case err != nil:
			// A log that does not hold together is not an absence of
			// revocation. A withheld revocation looks exactly like this, so
			// the only safe reading is that the status is unknown.
			out.Checks["not_revoked"] = false
			out.Errors = append(out.Errors, fmt.Sprintf("the credential's transaction log could "+
				"not be read, so whether it is still valid is unknown: %v", err))
		case status == keri.StatusRevoked:
			out.Checks["not_revoked"] = false
			out.Errors = append(out.Errors, "the credential has been revoked by its issuer")
		default:
			out.Checks["not_revoked"] = true
		}
	} else if cred.Registry != "" {
		// Issued into a registry, and the log was not supplied. Reported rather
		// than passed over: the credential could have been revoked an hour ago
		// and nothing here would know.
		out.Checks["not_revoked"] = nil
	}

	// A presentation is the holder proving it controls the subject identity.
	// Without it, a verified credential says only that it was issued — anybody
	// holding a copy could present it.
	if req.PresentationSaid != "" && req.CesrSignature != "" && req.HolderPublicKey != "" {
		if err := e.checkPresentation(req, cred, out); err != nil {
			return nil, err
		}
	}

	out.Verified = len(out.Errors) == 0
	return out, nil
}

// checkPresentation decides whether whoever handed over this credential is the
// subject of it.
//
// The signature is the last step, not the check. Verifying a signature over
// caller-supplied bytes under a caller-supplied key establishes only that the
// caller can sign with a key they chose — which anybody can do, including
// somebody presenting a copy of a stranger's credential. Three bindings have to
// hold before the signature means anything:
//
//   - the presentation must be intact, so its identifier re-derives from its
//     own body;
//   - it must name THIS credential and THIS subject, or it is a valid proof of
//     possession of something else;
//   - the key must be the one the subject's key log puts in force, rather than
//     one the presenter picked.
//
// Each is reported by name, because "the presentation failed" leaves a caller
// unable to tell a forgery from a stale key or a missing key log.
func (e *Engine) checkPresentation(
	req *drivers.DriverVerifyCredentialRequest,
	cred *keri.Credential,
	out *drivers.DriverVerifyCredentialResponse,
) error {
	signed, err := iacrypto.DecodeBase64(req.PresentationSaid)
	if err != nil {
		return fmt.Errorf("the presented bytes are not base64: %w", err)
	}

	if len(req.PresentationBody) == 0 {
		// Refused rather than falling back to the bare signature check. A
		// signature that binds to nothing is not weaker evidence than one that
		// binds; it is evidence of nothing at all, and reporting it as a passed
		// check is how a replayed credential gets accepted.
		out.Checks["presentation"] = false
		out.Errors = append(out.Errors, "the presentation was not supplied, only a signature over "+
			"it; a signature on its own cannot show which credential was presented or by whom")
		return nil
	}

	body, said, err := reduceePresentation(req.PresentationBody)
	if err != nil {
		out.Checks["presentation_intact"] = false
		out.Errors = append(out.Errors, fmt.Sprintf("the presentation does not hold together: %v", err))
		return nil
	}
	out.Checks["presentation_intact"] = true

	// What it is a presentation OF.
	if body.A.CredentialSAID != cred.SAID {
		out.Checks["presentation_binds_credential"] = false
		out.Errors = append(out.Errors, fmt.Sprintf("the presentation is of credential %s, not %s; "+
			"a proof of possession of a different credential says nothing about this one",
			body.A.CredentialSAID, cred.SAID))
	} else {
		out.Checks["presentation_binds_credential"] = true
	}

	// Who it is a presentation BY. The subject named in the credential is the
	// only identity a presentation of it can be made by.
	subject := firstNonEmpty(cred.Recipient, req.HolderAid)
	if subject != "" && body.I != subject {
		out.Checks["presentation_binds_holder"] = false
		out.Errors = append(out.Errors, fmt.Sprintf("the presentation is made by %s, but the "+
			"credential is about %s", body.I, subject))
	} else {
		out.Checks["presentation_binds_holder"] = true
	}

	// The signature has to be over this presentation's identifier, which is
	// what ties the proof to this presentation rather than to a credential
	// anyone holding a copy could re-present.
	if string(signed) != said {
		out.Checks["presentation"] = false
		out.Errors = append(out.Errors, "the signature is over something other than this "+
			"presentation, so it could have been lifted from another exchange")
		return nil
	}

	pub, err := normaliseKey(req.HolderPublicKey, true)
	if err != nil {
		return fmt.Errorf("the holder's key: %w", err)
	}

	// The key must be established, not asserted. Without this the presenter
	// chooses the key the signature is checked against, and every signature
	// verifies.
	if len(req.HolderKelEvents) > 0 && subject != "" {
		kel, err := e.ValidateKEL(subject, req.HolderKelEvents)
		if err != nil {
			return err
		}
		switch {
		case !kel.KelVerified:
			out.Checks["holder_key_established"] = false
			out.Errors = append(out.Errors, "the subject's key log does not establish a current "+
				"key, so the key this presentation was signed with is only claimed: "+
				joinErrors(kel.ValidationErrors))
		case kel.CurrentPublicKey != req.HolderPublicKey:
			out.Checks["holder_key_established"] = false
			out.Errors = append(out.Errors, fmt.Sprintf("the presentation is signed with %s, but "+
				"%s currently has %s in force", req.HolderPublicKey, subject, kel.CurrentPublicKey))
		default:
			out.Checks["holder_key_established"] = true
		}
	} else {
		// Named rather than silently absent. A caller reading a passed
		// presentation check would otherwise believe the signer was shown to
		// be the subject, when all that was shown is that they hold some key.
		out.Checks["holder_key_established"] = nil
		out.Errors = append(out.Errors, fmt.Sprintf("no key log was supplied for %s, so the key "+
			"this presentation was signed with has not been shown to be theirs", subject))
	}

	sig, err := signatureBytes(req.CesrSignature)
	if err != nil {
		return err
	}
	ok := keri.VerifySignature(pub, signed, sig) == nil
	out.Checks["presentation"] = ok
	if !ok {
		out.Errors = append(out.Errors, "the presentation is not signed by the holder's key, "+
			"so whoever presented this credential has not shown they control it")
	}
	return nil
}

// reduceePresentation reads a presentation back into the shape it was built in
// and recomputes its identifier.
//
// Going through the struct rather than the map is deliberate: the identifier is
// a digest over the fields in a fixed order, and a map has no order. Anything
// that re-serialised the map directly would compute a digest nobody else does
// and report every genuine presentation as altered.
func reduceePresentation(raw map[string]interface{}) (presentationBody, string, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return presentationBody{}, "", err
	}
	var body presentationBody
	if err := json.Unmarshal(encoded, &body); err != nil {
		return presentationBody{}, "", fmt.Errorf("it is not shaped like a presentation: %w", err)
	}
	claimed := body.D
	if claimed == "" {
		return presentationBody{}, "", fmt.Errorf("it carries no identifier")
	}

	// Recompute exactly as it was built: the attribute block's own identifier
	// first, then the body with its identifier blanked.
	attrs := body.A
	attrs.D = ""
	attrSAID, err := saidOfCompact(attrs)
	if err != nil {
		return presentationBody{}, "", err
	}
	if attrSAID != body.A.D {
		return presentationBody{}, "", fmt.Errorf("its attributes do not match the identifier " +
			"they carry, so what it says about the credential or the holder has been changed")
	}
	check := body
	check.D = ""
	recomputed, err := saidOfCompact(check)
	if err != nil {
		return presentationBody{}, "", err
	}
	if recomputed != claimed {
		return presentationBody{}, "", fmt.Errorf("it claims to be %s but its contents derive %s",
			claimed, recomputed)
	}
	return body, claimed, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func joinErrors(errs []string) string {
	if len(errs) == 0 {
		return "no detail was reported"
	}
	out := errs[0]
	for _, e := range errs[1:] {
		out += "; " + e
	}
	return out
}

// registryNonce produces the value that distinguishes one registry from another
// founded by the same issuer.
func registryNonce() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("could not read randomness for a registry nonce: %w", err)
	}
	return keri.MatterQB64(keri.CodeBlake3_256, raw)
}

// stampedClaims fills in the issuance timestamp a credential's claims must
// carry.
//
// The KERI library refuses to supply it, deliberately: a timestamp it invented
// would make the credential unreproducible by the caller that asked for it.
// Here the engine IS acting for the issuer, and the issuer is the authority on
// when it issued something, so stamping is correct.
//
// A caller that supplies its own is left alone. That is the case where the
// credential has to be reproducible — reissued identically, or its identifier
// computed ahead of issuing it — and overwriting the timestamp would defeat it.
func stampedClaims(claims map[string]interface{}) (json.RawMessage, error) {
	stamped := make(map[string]interface{}, len(claims)+1)
	for k, v := range claims {
		stamped[k] = v
	}
	if dt, ok := stamped["dt"].(string); !ok || dt == "" {
		stamped["dt"] = time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")
	}
	data, err := json.Marshal(stamped)
	if err != nil {
		return nil, fmt.Errorf("the claims cannot be encoded: %w", err)
	}
	return data, nil
}
