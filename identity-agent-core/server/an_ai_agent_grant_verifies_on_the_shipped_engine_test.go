package server

import (
	"encoding/base64"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// Every event the organisation wrote into its own log — approving the agent,
// opening the registry, issuing the grant — is signed, so the whole log verifies
// to somebody who has only the log.
func TestTheOrganisationsOwnEventsAreSigned(t *testing.T) {
	s, agent := grantWorld(t)
	if _, err := s.issueCapabilityGrant(agent, authority{}); err != nil {
		t.Fatal(err)
	}
	events, _ := s.DataStore.GetEvents(agent.DelegatorAID)
	if len(events) < 4 {
		t.Fatalf("expected founding, approval, registry and issuance; got %d events", len(events))
	}
	in := drivers.ValidateKELInput{AID: agent.DelegatorAID}
	for _, ev := range events {
		if ev.CesrSignature == "" || ev.RawBytesB64 == "" {
			t.Fatalf("event %d (%s) is stored without its bytes or its signature", ev.SequenceNumber, ev.EventType)
		}
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		in.RawEvents = append(in.RawEvents, raw)
		in.CesrSignatures = append(in.CesrSignatures, ev.CesrSignature)
	}
	got, err := drivers.ValidateKELFromBytes(in)
	if err != nil || !got.KelVerified {
		t.Fatalf("the organisation's log does not verify: %v %v", err, got.ValidationErrors)
	}
}

func scopesFor(t *testing.T, s *CoreServer, a *asset.Asset, grantSAID, token string) []string {
	t.Helper()
	seedAgentToken(t, s, token, mcpToken{
		Name: a.DisplayName, Scopes: []string{"infra.zone.list", "system.info.read"},
		AgentAID: a.PairwiseAID, DelegatorAID: a.DelegatorAID, GrantSAID: grantSAID,
	})
	return tokenAwareResolver{s}.Resolve(reqWithBearer(token)).Scopes
}

// The defect this replaces: verification required check names only a retired
// engine reported, so on the engine that ships every agent holding a grant was
// denied. Issued and verified for real, the grant now decides the agent's scopes.
func TestAnAIAgentGrantIsIssuedAndVerifiedOnTheShippedEngine(t *testing.T) {
	s, agent := grantWorld(t)
	grant, err := s.issueCapabilityGrant(agent, authority{})
	if err != nil {
		t.Fatalf("issuing the grant: %v", err)
	}
	rec, _ := s.DataStore.GetCredential(grant)
	if rec == nil || rec.SchemaSAID != capabilityGrantSchemaSAID {
		t.Fatalf("the grant was not stored under the AI agent grant schema: %+v", rec)
	}

	got := scopesFor(t, s, agent, grant, "iamcp_real")
	if len(got) != 2 || got[0] != "infra.zone.list" || got[1] != "system.info.read" {
		t.Fatalf("the agent's scopes should come from its verified grant, got %v", got)
	}
}

// Narrowing a ceiling withdraws the wider grant it replaces, so the old one
// cannot be found and used beside the new.
func TestReissuingAGrantRevokesTheOneItReplaces(t *testing.T) {
	s, agent := grantWorld(t)
	first, err := s.issueCapabilityGrant(agent, authority{})
	if err != nil {
		t.Fatal(err)
	}
	agent.Capabilities = []string{"system.info.read"}
	second, err := s.issueCapabilityGrant(agent, authority{})
	if err != nil {
		t.Fatal(err)
	}

	if old, _ := s.DataStore.GetCredential(first); old == nil || old.Status != "revoked" {
		t.Fatalf("the replaced grant is still %q", old.Status)
	}
	if got := scopesFor(t, s, agent, first, "iamcp_old"); len(got) != 0 {
		t.Fatalf("the replaced, wider grant still admits %v", got)
	}
	if got := scopesFor(t, s, agent, second, "iamcp_new"); len(got) != 1 || got[0] != "system.info.read" {
		t.Fatalf("the new grant admits %v", got)
	}
	if ref := s.findCapabilityGrant(agent.PairwiseAID); ref == nil || ref.SAID != second {
		t.Fatalf("the agent's grant resolves to %+v, not the newest", ref)
	}
	if st := s.agentStatus(agent.PairwiseAID); st != "active" {
		t.Fatalf("an agent whose grant was replaced reads as %q", st)
	}
}

// A grant past its valid_until admits nothing.
func TestALapsedGrantAdmitsNothing(t *testing.T) {
	s, agent := grantWorld(t)
	lapsed := mustParseTime(t, "2020-01-01T00:00:00Z")
	agent.GrantValidUntil = &lapsed
	grant, err := s.issueCapabilityGrant(agent, authority{})
	if err != nil {
		t.Fatal(err)
	}
	if got := scopesFor(t, s, agent, grant, "iamcp_lapsed"); len(got) != 0 {
		t.Fatalf("a lapsed grant admits %v", got)
	}
}

// Constraints in a shape the gateway does not enforce are refused rather than
// recorded as a limit the agent is not held to.
func TestConstraintsTheGatewayCannotEnforceAreRefused(t *testing.T) {
	caps := []string{"infra.dns_record.list"}
	for name, rc := range map[string]map[string]interface{}{
		"another shape": {"zones": map[string]interface{}{"example.com": true}, "valid_days": 30.0},
		"an empty list": {"infra.dns_record.list": map[string]interface{}{"zone_id": []interface{}{}}},
		"an empty map":  {"infra.dns_record.list": map[string]interface{}{}},
		"a capability the grant does not give": {
			"infra.dns_record.delete": map[string]interface{}{"zone_id": []interface{}{"z1"}}},
	} {
		if checkResourceConstraints(rc, caps) == nil {
			t.Fatalf("constraints with %s were accepted", name)
		}
	}
	if err := checkResourceConstraints(map[string]interface{}{
		"infra.dns_record.list": map[string]interface{}{"zone_id": []interface{}{"z1"}},
	}, caps); err != nil {
		t.Fatalf("enforceable constraints were refused: %v", err)
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A grant is checked against the issuer's log up to the event that issued it.
// An event written later that cannot be verified does not withdraw it — and
// before this, one unsigned event anywhere in the log denied every AI agent.
func TestALaterUnsignedEventDoesNotWithdrawAGrant(t *testing.T) {
	s, agent := grantWorld(t)
	grant, err := s.issueCapabilityGrant(agent, authority{})
	if err != nil {
		t.Fatal(err)
	}
	events, _ := s.DataStore.GetEvents(agent.DelegatorAID)
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID: agent.DelegatorAID, SequenceNumber: len(events), EventType: "ixn",
		EventJSON: `{"d":"ELATER","t":"ixn"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if got := scopesFor(t, s, agent, grant, "iamcp_later"); len(got) != 2 {
		t.Fatalf("a later unsigned event withdrew the grant: %v", got)
	}
}

// A grant counts only from the identity that delegated the AI agent.
func TestAGrantFromAnotherIssuerAdmitsNothing(t *testing.T) {
	s, agent := grantWorld(t)
	grant, err := s.issueCapabilityGrant(agent, authority{})
	if err != nil {
		t.Fatal(err)
	}
	// The same grant, presented for an AI agent that a different identity
	// delegated: its issuer is not that AI agent's delegator.
	elsewhere := *agent
	elsewhere.DelegatorAID = "ESOMEBODYELSE"
	if got := scopesFor(t, s, &elsewhere, grant, "iamcp_foreign"); len(got) != 0 {
		t.Fatalf("a grant from another issuer admits %v", got)
	}
}
