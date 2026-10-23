package server

import (
	"fmt"
	"log"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
)

// issueAssetCredential issues one credential built from the asset template —
// a grant, or a body binding — from the owner's registry to an asset, and does
// everything that makes it provable: the attributes are checked against the
// schema first, it is issued only into a registry so it can be withdrawn, it is
// stored, and the event that anchors it in the owner's log is stored signed.
//
// One path for every asset credential, so a rule added for one kind — a check,
// a signature, a lapse — reaches all of them.
//
// by is who authorised it, written into the credential where its schema admits
// it: an edge to their machine's Controller Grant and the request they signed.
func (s *CoreServer) issueAssetCredential(
	kind *schemas.AssetGrant, holder, issuer string, claims map[string]interface{}, expiry string, by authority,
) (string, error) {
	if s.KeriDriver == nil {
		return "", fmt.Errorf("keri driver unavailable")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", fmt.Errorf("no owner identity")
	}
	// Issuing as the identity writes into its key log, which only the holder
	// of its key may sign. Where that is another device nothing is written
	// here: a grant is prepared for that device to sign, and anything else
	// says why it cannot be done here.
	keyHere := true
	if issuer == identity.AID {
		if _, err := s.identitySigningSeed(); err != nil {
			keyHere = false
		}
	}
	claims["i"] = holder
	claims["asset_type"] = kind.AssetType
	if expiry != "" {
		claims["valid_until"] = expiry
	}
	// One request authorises one credential.
	var requestDigest string
	if by.Request != nil && kind.HasEdges() {
		requestDigest = iacrypto.Blake3QB64Must([]byte(by.Request.Signed))
		if used, err := s.DataStore.CredentialRequestUsed(requestDigest); err != nil || used {
			return "", fmt.Errorf("this request already authorised a credential, and authorises no other")
		}
	}
	edges := by.name(kind, claims)
	if err := kind.CheckAttributes(claims); err != nil {
		return "", err
	}
	// Issue into the owner's registry, so the credential is revoked by an event
	// in that registry's log, anchored in the owner's key log, which anybody can
	// check. There is no unrevocable fallback: a credential that cannot be
	// withdrawn is not one this software issues for an asset. Where the key is
	// elsewhere a registry not yet made cannot be made here either.
	var registrySAID string
	if keyHere {
		if registrySAID, err = s.ensureRegistry(issuer); err != nil {
			return "", fmt.Errorf("no registry to issue in: %w", err)
		}
	} else if reg, err := s.DataStore.GetRegistryByIssuer(issuer); err == nil && reg != nil && reg.VcpRawB64 != "" {
		registrySAID = reg.RegistrySAID
	} else {
		// No registry yet: its inception is asked of the device that holds
		// the key first, and the grant is built on it once it is signed.
		preparer, can := s.KeriDriver.(drivers.PreparedIssuer)
		if !can || (kind != schemas.AIAgentGrant && kind != schemas.ControllerGrant) {
			return "", errKeyElsewhere
		}
		reg, err := preparer.PrepareRegistryInception(issuer)
		if err != nil {
			return "", err
		}
		if _, err := s.awaitRegistry(reg, grantSpec{Schema: kind.Schema.SAID, Issuer: issuer, Claims: claims, Edges: edges,
			Holder: holder, Expiry: expiry, RequestDigest: requestDigest, About: by.About, Grant: by.ControllerGrant, Request: by.Request}); err != nil {
			return "", err
		}
		return "", errKeyElsewhere
	}
	preparer, canPrepare := s.KeriDriver.(drivers.PreparedIssuer)
	if !canPrepare {
		if !keyHere {
			return "", errKeyElsewhere
		}
		// The issuance and its anchor are kept first, together. A credential
		// whose issuance cannot be proved is not issued.
		keptInside := s.engineKeepsCredentialLogs()
		result, err := s.KeriDriver.IssueCredentialInRegistry(issuer, claims, kind.Schema.SAID, holder, edges, registrySAID)
		if err == nil && !keptInside {
			err = s.keepAfter(issuer, result.SequenceNumber, result.IxnRawBytesB64, result.IssRawBytesB64)
		}
		if err != nil {
			return "", fmt.Errorf("%s was not issued: %w", kind.Schema.Name, err)
		}
		return s.finishIssuance(kind, result, holder, issuer, expiry, registrySAID, requestDigest, by)
	}
	// Built first and checked against the request it rests on before anything
	// is written, so a credential that does not rest on its request never
	// reaches the key log, rather than being issued and withdrawn.
	prepared, err := preparer.PrepareCredentialInRegistry(issuer, claims, kind.Schema.SAID, holder, edges, registrySAID)
	if err != nil {
		return "", fmt.Errorf("%s was not issued: %w", kind.Schema.Name, err)
	}
	if err := s.checkAuthorisationOf(prepared.AcdcRaw, issuer, "", "", by); err != nil {
		return "", fmt.Errorf("%s was not issued: it does not rest on the request that asked for it: %w", kind.Schema.Name, err)
	}
	if !keyHere {
		if kind != schemas.AIAgentGrant && kind != schemas.ControllerGrant {
			return "", errKeyElsewhere
		}
		if _, err := s.awaitSignature(kind, prepared, grantSpec{Schema: kind.Schema.SAID, Issuer: issuer, Claims: claims, Edges: edges,
			Holder: holder, Expiry: expiry, RequestDigest: requestDigest, About: by.About, Grant: by.ControllerGrant, Request: by.Request}); err != nil {
			return "", err
		}
		return "", errKeyElsewhere
	}
	s.engineKeepsCredentialLogs()
	result, err := preparer.AppendPreparedIssuance(issuer, prepared)
	if err != nil {
		return "", fmt.Errorf("%s was not issued: %w", kind.Schema.Name, err)
	}
	return s.finishIssuance(kind, result, holder, issuer, expiry, registrySAID, requestDigest, by)
}

// finishIssuance records a credential just appended: the credential, the
// request it was issued on, and the check of it against that request with the
// order of events read from the key log.
func (s *CoreServer) finishIssuance(kind *schemas.AssetGrant, result *drivers.DriverIssueCredentialResponse,
	holder, issuer, expiry, registrySAID, requestDigest string, by authority) (string, error) {
	// Fixed-width to the nanosecond, so two credentials issued in one second
	// still order correctly as text, which is how the newest is picked.
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	if err := s.DataStore.SaveCredential(store.CredentialRecord{
		SAID:           result.AcdcSaid,
		IssuerAID:      issuer,
		HolderAID:      holder,
		SchemaSAID:     kind.Schema.SAID,
		AcdcJson:       result.AcdcJsonB64,
		IxnSAID:        result.IxnSaid,
		IssuedAt:       now,
		Status:         "issued",
		Format:         "acdc",
		CredentialType: kind.Schema.Name,
		ExpiryDate:     expiry,
		RegistrySAID:   registrySAID,
		IssSAID:        result.IssSaid,
	}); err != nil {
		log.Printf("[asset] failed to persist %s %s: %v", kind.Schema.Name, result.AcdcSaid, err)
	}
	// The request is kept with the credential; a request that has authorised
	// another meanwhile is refused here.
	if requestDigest != "" {
		if err := s.DataStore.KeepCredentialRequest(result.AcdcSaid, requestDigest, by.Request.Body); err != nil {
			s.withdrawIssued(result.AcdcSaid)
			return "", fmt.Errorf("%s was not issued: %w", kind.Schema.Name, err)
		}
	}
	// The rule anybody will apply to it later, applied now with the order of
	// events read from where each is anchored.
	if err := s.checkAuthorisation(result.AcdcSaid, by); err != nil {
		s.withdrawIssued(result.AcdcSaid)
		return "", fmt.Errorf("%s was not issued: it does not rest on the request that asked for it: %w", kind.Schema.Name, err)
	}
	// The interaction anchoring it goes to the identity's witnesses.
	s.witnessOwnLog()
	return result.AcdcSaid, nil
}

// withdrawIssued revokes a credential just issued that is not to be handed
// out, and marks it so whatever the registry says.
func (s *CoreServer) withdrawIssued(said string) {
	if rec, _ := s.DataStore.GetCredential(said); rec != nil {
		if _, err := s.revokeIssuedCredential(rec); err != nil {
			log.Printf("[asset] %s was issued and is not to be used, and its revocation failed: %v", said, err)
		}
		_ = s.DataStore.UpdateCredentialStatus(said, "revoked")
	}
}
