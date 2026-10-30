package server

import (
	"sort"
	"time"

	"identity-agent-core/internal/coretypes"
	"identity-agent-core/schemas"
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
	return s.credentialsOfAnyHeldBy(holder, []string{schema}, issuer, usableOnly)
}

// credentialsOfAnyHeldBy is credentialsHeldBy for a credential that has more
// than one schema version still honoured.
func (s *CoreServer) credentialsOfAnyHeldBy(holder string, schemaSAIDs []string, issuer string, usableOnly bool) []store.CredentialRecord {
	wanted := map[string]bool{}
	for _, said := range schemaSAIDs {
		if said != "" {
			wanted[said] = true
		}
	}
	if s.DataStore == nil || holder == "" || len(wanted) == 0 {
		return nil
	}
	creds, err := s.DataStore.GetCredentials()
	if err != nil {
		return nil
	}
	var out []store.CredentialRecord
	for _, c := range creds {
		if c.HolderAID != holder || !wanted[c.SchemaSAID] {
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
	return s.credentialsOfAnyHeldBy(agentAID, capabilityGrantSchemaSAIDs, s.OwnerRootAID(), usableOnly)
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

// capabilityGrantSchemaSAID identifies the AI agent grant schema (see the schema
// package's asset grants). The owner issues an ACDC of this schema to a
// provisioned agent; the endpoint verifies it to prove the agent's authority at
// invoke time.
var capabilityGrantSchemaSAID = schemas.AIAgentGrant.Schema.SAID

// capabilityGrantSchemaSAIDs are every version of the grant schema still
// honoured: the current one, and the first, which grants issued before edges
// carry.
var capabilityGrantSchemaSAIDs = []string{capabilityGrantSchemaSAID, schemas.AIAgentGrantV1.Schema.SAID}

// OwnerRootAID returns the owner's root AID (the delegator every provisioned agent
// chains to), or "" if no identity is established. Exported for overlay governance.
func (s *CoreServer) OwnerRootAID() string {
	if s.DataStore == nil {
		return ""
	}
	id, err := s.DataStore.GetIdentity()
	if err != nil || id == nil {
		return ""
	}
	return id.AID
}

// HoldsValidCredential reports whether aid holds an unrevoked credential of the given
// schema (and, when issuer != "", from that issuer). Exported so an overlay's
// credential-gated access policy can consult it. Trusts the stored credential's status
// (sound for credentials this agent issued; verifying a foreign-issuer presented
// credential is a separate extension).
func (s *CoreServer) HoldsValidCredential(aid, schema, issuer string) bool {
	return len(s.credentialsHeldBy(aid, schema, issuer, true)) > 0
}

// findCapabilityGrant returns the newest usable capability-grant credential held by aid.
func (s *CoreServer) findCapabilityGrant(aid string) *coretypes.GrantRef {
	held := s.grantsHeldBy(aid, true)
	if len(held) == 0 {
		return nil
	}
	return &coretypes.GrantRef{SAID: held[0].SAID}
}
