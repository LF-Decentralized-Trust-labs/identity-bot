package server

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
)

func newGrantTestServer(t *testing.T) *CoreServer {
	t.Helper()
	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir(), DataStore: st}
}

func seedAgentToken(t *testing.T, s *CoreServer, plaintext string, tok mcpToken) {
	t.Helper()
	tok.Hash = hashMCPToken(plaintext)
	mcpTokensMu.Lock()
	defer mcpTokensMu.Unlock()
	if err := s.saveMCPTokens([]mcpToken{tok}); err != nil {
		t.Fatal(err)
	}
}

// capabilitiesFromACDC pulls the granted ids out of the ACDC attribute block,
// and nowhere else, and rejects garbage.
func TestCapabilitiesFromACDC(t *testing.T) {
	acdc, _ := json.Marshal(map[string]interface{}{
		"a": map[string]interface{}{
			"i":            "EAgent",
			"capabilities": []interface{}{"infra.zone.list", "infra.dns_record.list"},
		},
	})
	got := capabilitiesFromACDC(base64.StdEncoding.EncodeToString(acdc))
	if len(got) != 2 || got[0] != "infra.zone.list" || got[1] != "infra.dns_record.list" {
		t.Fatalf("expected 2 caps from the a-block, got %v", got)
	}

	flat, _ := json.Marshal(map[string]interface{}{"capabilities": []interface{}{"x.y.z"}})
	if got := capabilitiesFromACDC(base64.StdEncoding.EncodeToString(flat)); len(got) != 0 {
		t.Fatalf("capabilities outside the attribute block were read: %v", got)
	}

	if got := capabilitiesFromACDC("not-base64!!!"); got != nil {
		t.Fatalf("garbage input should yield nil, got %v", got)
	}
}

// Without the KERI driver, an agent token that carries a grant SAID still governs
// by its stored ceiling (increment-1 behaviour) — driverless builds keep working.
func TestAgentGrantFallsBackWithoutDriver(t *testing.T) {
	s := newGrantTestServer(t) // KeriDriver nil
	plaintext := "iamcp_nodriver"
	seedAgentToken(t, s, plaintext, mcpToken{
		Name: "a1", Scopes: []string{"infra.zone.list"},
		AgentAID: "EAgent", DelegatorAID: "ERoot", GrantSAID: "EGrant123",
	})

	cc := tokenAwareResolver{s}.Resolve(reqWithBearer(plaintext))
	if cc.CallerAID != "EAgent" {
		t.Fatalf("caller should be the agent AID, got %q", cc.CallerAID)
	}
	if len(cc.Scopes) != 1 || cc.Scopes[0] != "infra.zone.list" {
		t.Fatalf("driverless agent token should keep the stored ceiling, got %v", cc.Scopes)
	}
	if cc.GrantSAID != "" {
		t.Fatalf("no credential was verified, so GrantSAID must be empty, got %q", cc.GrantSAID)
	}
}

// A revoked grant denies: the credential resolves but its status is unusable, so
// scopes are cleared and the gateway default-denies. (The driver is never
// invoked — the record status is checked first.)
func TestRevokedGrantDenies(t *testing.T) {
	s := newGrantTestServer(t)
	s.KeriDriver = keriengine.New() // non-nil, not called on this path
	s.engineSigns()
	if err := s.DataStore.SaveCredential(store.CredentialRecord{
		SAID: "EGrantRevoked", Status: "revoked", Format: "acdc",
		SchemaSAID: capabilityGrantSchemaSAID, HolderAID: "EAgent", IssuerAID: "ERoot",
	}); err != nil {
		t.Fatal(err)
	}
	plaintext := "iamcp_revoked"
	seedAgentToken(t, s, plaintext, mcpToken{
		Name: "a2", Scopes: []string{"infra.zone.list"},
		AgentAID: "EAgent", DelegatorAID: "ERoot", GrantSAID: "EGrantRevoked",
	})

	cc := tokenAwareResolver{s}.Resolve(reqWithBearer(plaintext))
	if len(cc.Scopes) != 0 {
		t.Fatalf("a revoked grant must yield no scopes (deny), got %v", cc.Scopes)
	}
}

// The happy path: a valid unrevoked grant whose issuer KEL resolves and whose
// ACDC the driver verifies → scopes are derived from the credential (not the
// stored ceiling) and grant_said is recorded. Uses a fake driver so the wiring
// is exercised independent of a live KERI keystore.
func TestVerifiedGrantDerivesScopesFromCredential(t *testing.T) {
	s := newGrantTestServer(t)
	s.KeriDriver = &driverfake.Engine{
		VerifyCredentialFunc: func(*drivers.DriverVerifyCredentialRequest) (*drivers.DriverVerifyCredentialResponse, error) {
			return &drivers.DriverVerifyCredentialResponse{
				Verified: true,
				AcdcSaid: "EGrantOK",
				// The names the shipped engine reports. Not revoked is absent:
				// no registry log was supplied, so the issuer's own record decides.
				Checks: map[string]interface{}{
					"structure": true, "schema_accepted": true, "holder": true, "issuer_kel": true,
				},
			}, nil
		},
	}

	// The issuer's stored log, which is what verification reads. The fake engine
	// does not inspect it; what is checked here is that the issuance is in it.
	for i, ev := range []string{`{"d":"ERoot"}`, `{"d":"EIssuance","a":[{"i":"EGrantOK","s":"0","d":"EIss"}]}`} {
		if err := s.DataStore.SaveEvent(store.EventRecord{
			AID: "ERoot", SequenceNumber: i, EventType: "ixn",
			EventJSON: ev, RawBytesB64: "eA==", CesrSignature: "sig",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The grant ACDC names infra.zone.list in its attribute block; the token
	// remembers more, so the narrower of the two is what must come out.
	acdc, _ := json.Marshal(map[string]any{
		"a": map[string]any{"i": "EAgent", "capabilities": []any{"infra.zone.list"}},
	})
	if err := s.DataStore.SaveCredential(store.CredentialRecord{
		SAID: "EGrantOK", Status: "issued", Format: "acdc",
		SchemaSAID: capabilityGrantSchemaSAID, HolderAID: "EAgent", IssuerAID: "ERoot",
		AcdcJson: base64.StdEncoding.EncodeToString(acdc), IxnSAID: "EIssuance", IssSAID: "EIss",
	}); err != nil {
		t.Fatal(err)
	}
	plaintext := "iamcp_verified"
	seedAgentToken(t, s, plaintext, mcpToken{
		Name: "a4", Scopes: []string{"infra.zone.list", "stored.but.not.granted"},
		AgentAID: "EAgent", DelegatorAID: "ERoot", GrantSAID: "EGrantOK",
	})

	cc := tokenAwareResolver{s}.Resolve(reqWithBearer(plaintext))
	if len(cc.Scopes) != 1 || cc.Scopes[0] != "infra.zone.list" {
		t.Fatalf("scopes must come from the verified credential, got %v", cc.Scopes)
	}
	if cc.GrantSAID != "EGrantOK" {
		t.Fatalf("grant_said should be recorded on a verified call, got %q", cc.GrantSAID)
	}
}

// A grant SAID that resolves to no credential denies, too.
func TestMissingGrantDenies(t *testing.T) {
	s := newGrantTestServer(t)
	s.KeriDriver = keriengine.New()
	s.engineSigns()
	plaintext := "iamcp_missing"
	seedAgentToken(t, s, plaintext, mcpToken{
		Name: "a3", Scopes: []string{"infra.zone.list"},
		AgentAID: "EAgent", DelegatorAID: "ERoot", GrantSAID: "ENoSuchGrant",
	})

	cc := tokenAwareResolver{s}.Resolve(reqWithBearer(plaintext))
	if len(cc.Scopes) != 0 {
		t.Fatalf("a missing grant must yield no scopes (deny), got %v", cc.Scopes)
	}
}
