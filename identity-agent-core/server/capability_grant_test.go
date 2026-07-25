package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

func newGrantTestServer(t *testing.T) *CoreServer {
	t.Helper()
	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &CoreServer{DataDir: t.TempDir(), DataStore: st}
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
// with a flat top-level fallback, and rejects garbage.
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
	if got := capabilitiesFromACDC(base64.StdEncoding.EncodeToString(flat)); len(got) != 1 || got[0] != "x.y.z" {
		t.Fatalf("flat fallback failed: %v", got)
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
	s.KeriDriver = &drivers.KeriDriver{} // non-nil, not called on this path
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
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/kel":
			json.NewEncoder(w).Encode(map[string]any{
				"aid": "ERoot", "sequence_number": 0, "event_count": 1,
				"kel": []map[string]any{{"t": "icp", "s": "0", "d": "ERoot", "i": "ERoot"}},
			})
		case r.URL.Path == "/credential/verify":
			json.NewEncoder(w).Encode(map[string]any{
				"verified":  true,
				"acdc_said": "EGrantOK",
				"checks": map[string]any{
					"said_integrity": true, "issuer_in_kel": true, "kel_chain_valid": true,
					"schema_trusted": true, "not_revoked": true, "holder_matches_subject": true,
					"presentation_sig_valid": false, "credential_anchored": true,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()

	// Point NewKeriDriver at the fake server (it builds BaseURL from the port).
	u, _ := url.Parse(fake.URL)
	t.Setenv("KERI_DRIVER_PORT", u.Port())

	s := newGrantTestServer(t)
	s.KeriDriver = drivers.NewKeriDriver()

	// The grant ACDC names infra.zone.list in its attribute block; the stored
	// token ceiling deliberately differs so we can prove the credential wins.
	acdc, _ := json.Marshal(map[string]any{
		"a": map[string]any{"i": "EAgent", "capabilities": []any{"infra.zone.list"}},
	})
	if err := s.DataStore.SaveCredential(store.CredentialRecord{
		SAID: "EGrantOK", Status: "issued", Format: "acdc",
		SchemaSAID: capabilityGrantSchemaSAID, HolderAID: "EAgent", IssuerAID: "ERoot",
		AcdcJson: base64.StdEncoding.EncodeToString(acdc),
	}); err != nil {
		t.Fatal(err)
	}
	plaintext := "iamcp_verified"
	seedAgentToken(t, s, plaintext, mcpToken{
		Name: "a4", Scopes: []string{"stored.ceiling.placeholder"},
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
	s.KeriDriver = &drivers.KeriDriver{}
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
