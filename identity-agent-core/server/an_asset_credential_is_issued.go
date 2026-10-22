package server

import (
	"fmt"
	"log"
	"time"

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
	if identity, err := s.DataStore.GetIdentity(); err != nil || identity == nil {
		return "", fmt.Errorf("no owner identity")
	}
	claims["i"] = holder
	claims["asset_type"] = kind.AssetType
	if expiry != "" {
		claims["valid_until"] = expiry
	}
	edges := by.name(kind, claims)
	if err := kind.CheckAttributes(claims); err != nil {
		return "", err
	}
	// Issue into the owner's registry, so the credential is revoked by an event
	// in that registry's log, anchored in the owner's key log, which anybody can
	// check. There is no unrevocable fallback: a credential that cannot be
	// withdrawn is not one this software issues for an asset.
	registrySAID, err := s.ensureRegistry(issuer)
	if err != nil {
		return "", fmt.Errorf("no registry to issue in: %w", err)
	}
	// The issuance and its anchor are kept first, together. A credential whose
	// issuance cannot be proved is not issued.
	keptInside := s.engineKeepsCredentialLogs()
	result, err := s.KeriDriver.IssueCredentialInRegistry(issuer, claims, kind.Schema.SAID, holder, edges, registrySAID)
	if err == nil && !keptInside {
		err = s.keepAfter(issuer, result.SequenceNumber, result.IxnRawBytesB64, result.IssRawBytesB64)
	}
	if err != nil {
		return "", fmt.Errorf("%s was not issued: %w", kind.Schema.Name, err)
	}
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
	// The rule anybody will apply to it later, applied now: a credential that
	// does not rest on the request it carries is withdrawn, not handed out.
	if err := s.checkAuthorisation(result.AcdcSaid, by); err != nil {
		if rec, _ := s.DataStore.GetCredential(result.AcdcSaid); rec != nil {
			if _, rerr := s.revokeIssuedCredential(rec); rerr != nil {
				log.Printf("[asset] %s %s does not rest on its request and its revocation failed: %v", kind.Schema.Name, result.AcdcSaid, rerr)
			}
			_ = s.DataStore.UpdateCredentialStatus(result.AcdcSaid, "revoked")
		}
		return "", fmt.Errorf("%s was not issued: it does not rest on the request that asked for it: %w", kind.Schema.Name, err)
	}
	return result.AcdcSaid, nil
}
