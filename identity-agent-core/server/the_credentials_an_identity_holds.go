package server

import (
	"sort"
	"time"

	"identity-agent-core/store"
)

// credentialsHeldBy is every stored credential of one schema held by one
// identifier, newest first. issuer, when not empty, keeps only those that
// issuer issued; usableOnly keeps only those whose status still stands.
//
// The one place this question is answered. Picking "the grant an AI agent
// holds" was written four times, each slightly differently — one compared
// issue times as text, which misorders two formats within a second — and a
// difference between copies is how a revoked grant gets found by one of them.
func (s *CoreServer) credentialsHeldBy(holder, schema, issuer string, usableOnly bool) []store.CredentialRecord {
	if s.DataStore == nil || holder == "" || schema == "" {
		return nil
	}
	creds, err := s.DataStore.GetCredentials()
	if err != nil {
		return nil
	}
	var out []store.CredentialRecord
	for _, c := range creds {
		if c.HolderAID != holder || c.SchemaSAID != schema {
			continue
		}
		if issuer != "" && c.IssuerAID != issuer {
			continue
		}
		if usableOnly && !isUsableStatus(c.Status) {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return issuedAt(out[i]).After(issuedAt(out[j]))
	})
	return out
}

// grantsHeldBy is the AI agent grants this identity issued to one AI agent,
// newest first.
func (s *CoreServer) grantsHeldBy(agentAID string, usableOnly bool) []store.CredentialRecord {
	return s.credentialsHeldBy(agentAID, capabilityGrantSchemaSAID, s.OwnerRootAID(), usableOnly)
}

// issuedAt reads a credential's issue time in either format it has been
// stored in: to the second, or fixed-width to the nanosecond. Unreadable sorts
// oldest, so it never outranks a grant whose time is known.
func issuedAt(c store.CredentialRecord) time.Time {
	t, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}
