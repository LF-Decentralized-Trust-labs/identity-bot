package keriengine

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"identity-agent-core/drivers"

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
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}

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
	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    id.AID,
		PriorSAID: id.LastSAID,
		SN:        id.SN + 1,
		Data:      []json.RawMessage{seal},
	})
	if err != nil {
		return nil, fmt.Errorf("anchoring the registry: %w", err)
	}
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, err
	}
	ixnBody, err := eventMap(ixn)
	if err != nil {
		return nil, err
	}
	ixnEntry, err := entry(ixn)
	if err != nil {
		return nil, err
	}

	e.state.mu.Lock()
	if id.Registries == nil {
		id.Registries = map[string]*registry{}
	}
	id.Registries[registrySAID] = &registry{
		SAID:         registrySAID,
		TEL:          map[string][][]byte{},
		IssuanceSAID: map[string]string{},
	}
	id.SN = int(ixnEvent.SN)
	id.LastSAID = ixnEvent.SAID
	id.KEL = append(id.KEL, ixnEntry)
	e.state.mu.Unlock()

	return &drivers.DriverRegistryInceptResponse{
		RegistrySaid:   registrySAID,
		VcpSaid:        vcpEvent.SAID,
		VcpEvent:       vcpBody,
		VcpJsonB64:     b64(vcp),
		IxnSaid:        ixnEvent.SAID,
		IxnEvent:       ixnBody,
		SequenceNumber: int(ixnEvent.SN),
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
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}
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
	acdcBody, err := eventMap(acdc)
	if err != nil {
		return nil, err
	}

	// What gets anchored depends on whether there is a registry. With one, the
	// issuance event is anchored and the credential's status is readable from
	// the registry. Without one, the credential itself is anchored, which
	// records that it was issued and leaves no place to record that it was not
	// revoked.
	var (
		issRaw  []byte
		issSAID string
		sealID  = cred.SAID
		sealSN  = "0"
	)
	if registrySaid != "" {
		issRaw, err = keri.BuildIssuance(keri.IssuanceInput{
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
		issSAID = issEvent.SAID
		sealID = cred.SAID
	}

	seal, err := eventSeal(sealID, sealSN, firstNonEmpty(issSAID, cred.SAID))
	if err != nil {
		return nil, err
	}
	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    id.AID,
		PriorSAID: id.LastSAID,
		SN:        id.SN + 1,
		Data:      []json.RawMessage{seal},
	})
	if err != nil {
		return nil, fmt.Errorf("anchoring the issuance: %w", err)
	}
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, err
	}
	ixnBody, err := eventMap(ixn)
	if err != nil {
		return nil, err
	}
	ixnEntry, err := entry(ixn)
	if err != nil {
		return nil, err
	}

	e.state.mu.Lock()
	if registrySaid != "" {
		reg := id.Registries[registrySaid]
		if reg == nil {
			reg = &registry{SAID: registrySaid, TEL: map[string][][]byte{}, IssuanceSAID: map[string]string{}}
			id.Registries[registrySaid] = reg
		}
		reg.TEL[cred.SAID] = append(reg.TEL[cred.SAID], issRaw)
		reg.IssuanceSAID[cred.SAID] = issSAID
	}
	id.SN = int(ixnEvent.SN)
	id.LastSAID = ixnEvent.SAID
	id.KEL = append(id.KEL, ixnEntry)
	e.state.mu.Unlock()

	return &drivers.DriverIssueCredentialResponse{
		AID:            id.AID,
		AcdcSaid:       cred.SAID,
		AcdcJsonB64:    b64(acdc),
		AcdcBody:       acdcBody,
		IxnRawBytesB64: b64(ixn),
		IxnSaid:        ixnEvent.SAID,
		IxnEvent:       ixnBody,
		SequenceNumber: int(ixnEvent.SN),
		IssSaid:        issSAID,
	}, nil
}

// RevokeCredential records that a credential is no longer valid.
func (e *Engine) RevokeCredential(name, acdcSaid, registrySaid, issSaid string) (*drivers.DriverRevokeCredentialResponse, error) {
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}
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
	revBody, err := eventMap(rev)
	if err != nil {
		return nil, err
	}

	seal, err := eventSeal(acdcSaid, "1", revEvent.SAID)
	if err != nil {
		return nil, err
	}
	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    id.AID,
		PriorSAID: id.LastSAID,
		SN:        id.SN + 1,
		Data:      []json.RawMessage{seal},
	})
	if err != nil {
		return nil, fmt.Errorf("anchoring the revocation: %w", err)
	}
	ixnEvent, err := keri.ParseEvent(ixn)
	if err != nil {
		return nil, err
	}
	ixnBody, err := eventMap(ixn)
	if err != nil {
		return nil, err
	}
	ixnEntry, err := entry(ixn)
	if err != nil {
		return nil, err
	}

	e.state.mu.Lock()
	if reg := id.Registries[registrySaid]; reg != nil {
		reg.TEL[acdcSaid] = append(reg.TEL[acdcSaid], rev)
	}
	id.SN = int(ixnEvent.SN)
	id.LastSAID = ixnEvent.SAID
	id.KEL = append(id.KEL, ixnEntry)
	e.state.mu.Unlock()

	return &drivers.DriverRevokeCredentialResponse{
		RevSaid:        revEvent.SAID,
		RevEvent:       revBody,
		IxnSaid:        ixnEvent.SAID,
		IxnEvent:       ixnBody,
		SequenceNumber: int(ixnEvent.SN),
	}, nil
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
	raw, err := decodeB64(req.AcdcJson)
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

	// A presentation is the holder proving it controls the subject identity.
	// Without it, a verified credential says only that it was issued — anybody
	// holding a copy could present it.
	if req.PresentationSaid != "" && req.CesrSignature != "" && req.HolderPublicKey != "" {
		signed, err := decodeB64(req.PresentationSaid)
		if err != nil {
			return nil, fmt.Errorf("the presented bytes are not base64: %w", err)
		}
		pub, err := normaliseKey(req.HolderPublicKey, true)
		if err != nil {
			return nil, fmt.Errorf("the holder's key: %w", err)
		}
		sig, err := signatureBytes(req.CesrSignature)
		if err != nil {
			return nil, err
		}
		ok := keri.VerifySignature(pub, signed, sig) == nil
		out.Checks["presentation"] = ok
		if !ok {
			out.Errors = append(out.Errors, "the presentation is not signed by the holder's key, "+
				"so whoever presented this credential has not shown they control it")
		}
	}

	out.Verified = len(out.Errors) == 0
	return out, nil
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
