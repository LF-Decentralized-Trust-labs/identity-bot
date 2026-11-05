package server

import (
	"bytes"
	"context"
	"encoding/json"
	"identity-agent-core/internal/coretypes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// issuedThenRevoked issues a grant in a registry held here and returns the
// server and the credential record, before it is revoked.
func issuedThenRevoked(t *testing.T) (*CoreServer, string, string, func()) {
	t.Helper()
	s, agent := grantWorld(t)
	said, err := s.issueCapabilityGrant(agent, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(said)
	if rec == nil || rec.RegistrySAID == "" {
		t.Fatalf("the grant was not issued into a registry: %+v", rec)
	}
	revoke := func() {
		if _, _, err := s.withdrawCredential(rec); err != nil {
			t.Fatal(err)
		}
	}
	return s, said, rec.AcdcJson, revoke
}

type chainAnswer struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
	Chain  []struct {
		Valid            bool   `json:"valid"`
		RevocationStatus string `json:"revocation_status"`
		RevocationReason string `json:"revocation_reason"`
	} `json:"chain"`
}

func verifyChainHere(t *testing.T, s *CoreServer, body map[string]any) chainAnswer {
	t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	s.handleVerifyCredentialChain(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if rec.Code != http.StatusOK {
		t.Fatalf("chain verify answered %d: %s", rec.Code, rec.Body.String())
	}
	var got chainAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// /credentials/verify refuses a credential revoked here, with the reason, and
// reads the same credential as live before it is revoked. Fails if the chain
// handler stops going through verifyCredentialHere.
func TestTheChainVerifierRefusesACredentialRevokedHere(t *testing.T) {
	s, said, acdc, revoke := issuedThenRevoked(t)

	live := verifyChainHere(t, s, map[string]any{"acdc_said": said})
	// Valid is not asserted: a credential issued here is verified against the
	// issuer's own key log in parsed form, which the engine does not accept,
	// whether or not the credential is revoked. Revocation is what is tested.
	if len(live.Chain) == 0 || live.Chain[0].RevocationStatus != revocationNotRevoked {
		t.Fatalf("a live credential read %+v", live)
	}

	revoke()
	for name, body := range map[string]map[string]any{
		"by said":  {"acdc_said": said},
		"by bytes": {"acdc_json_b64": acdc},
	} {
		got := verifyChainHere(t, s, body)
		if got.Valid || got.Chain[0].Valid {
			t.Errorf("%s: a credential revoked here still verified", name)
		}
		if got.Chain[0].RevocationStatus != revocationRevoked || got.Chain[0].RevocationReason == "" {
			t.Errorf("%s: step reads %q / %q", name, got.Chain[0].RevocationStatus, got.Chain[0].RevocationReason)
		}
		if !strings.Contains(strings.Join(got.Errors, "|"), "revoked") {
			t.Errorf("%s: the reply does not say why: %v", name, got.Errors)
		}
	}
}

// A credential from a registry not held here is reported as not checked by the
// chain verifier, never as not revoked.
func TestTheChainVerifierReportsNotCheckedForAForeignRegistry(t *testing.T) {
	issuer, agent := grantWorld(t)
	said, err := issuer.issueCapabilityGrant(agent, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := issuer.DataStore.GetCredential(said)
	verifier, _ := grantWorld(t)
	got := verifyChainHere(t, verifier, map[string]any{"acdc_json_b64": rec.AcdcJson})
	if got.Chain[0].RevocationStatus != revocationNoRegistryState {
		t.Fatalf("status %q, want %q", got.Chain[0].RevocationStatus, revocationNoRegistryState)
	}
}

// A login presented with a credential this agent revoked is refused, and the
// refusal says why. Fails if the login path stops going through
// verifyCredentialHere.
func TestALoginPresentedWithARevokedCredentialIsRefusedAndSaysWhy(t *testing.T) {
	s, _, acdc, revoke := issuedThenRevoked(t)

	// A live credential issued here is not accepted either, for a reason that
	// is not revocation (see the chain test); it must not be called revoked.
	_, _, reason := s.verifyPresentedCredentialACDC(context.Background(), acdc, "", "", "", "", nil)
	if strings.Contains(reason, "revoked") {
		t.Fatalf("a live credential was called revoked at login: %s", reason)
	}

	revoke()
	ok, _, reason := s.verifyPresentedCredentialACDC(context.Background(), acdc, "", "", "", "", nil)
	if ok {
		t.Fatal("a login was accepted with a credential revoked here")
	}
	if !strings.Contains(reason, "revoked") {
		t.Fatalf("the refusal does not say why: %q", reason)
	}
}

// The same refusal reaches the credential gate a login passes through, and the
// declared-field fallback (no credential bytes sent) does not outweigh this
// agent's own record of the revocation.
func TestTheLoginGateRefusesARevokedCredentialWithOrWithoutItsBytes(t *testing.T) {
	s, said, acdc, revoke := issuedThenRevoked(t)
	const schema = "ESchemaTheSiteRequires"
	with := []interface{}{map[string]interface{}{"said": said, "schema_said": schema, "status": "issued", "acdc_json_b64": acdc}}
	without := []interface{}{map[string]interface{}{"said": said, "schema_said": schema, "status": "issued"}}

	if ok, _ := s.credentialGateSatisfied(context.Background(), without, schema, ""); !ok {
		t.Fatal("a live credential's declared status was refused")
	}
	revoke()
	for name, presented := range map[string][]interface{}{"with bytes": with, "declared only": without} {
		ok, reason := s.credentialGateSatisfied(context.Background(), presented, schema, "")
		if ok {
			t.Errorf("%s: the gate admitted a credential revoked here", name)
		}
		if !strings.Contains(reason, "revoked") {
			t.Errorf("%s: the refusal does not say why: %q", name, reason)
		}
	}
}
