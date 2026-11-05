package server

import (
	"bytes"
	"encoding/json"
	"identity-agent-core/internal/coretypes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type verifyAnswer struct {
	Verified         bool                   `json:"verified"`
	Checks           map[string]interface{} `json:"checks"`
	Errors           []string               `json:"errors"`
	AcdcSaid         string                 `json:"acdc_said"`
	RevocationStatus string                 `json:"revocation_status"`
	RevocationReason string                 `json:"revocation_reason"`
}

func verifyHere(t *testing.T, s *CoreServer, acdcB64 string) verifyAnswer {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"acdc_json": acdcB64})
	rec := httptest.NewRecorder()
	s.handleVerifyCredential(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify answered %d: %s", rec.Code, rec.Body.String())
	}
	var got verifyAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// A credential this agent issued and then revoked is refused when it is
// presented back to it, with the reason in the reply. Fails if the registry
// log is not supplied to the engine: it then reads "not checked", not revoked.
func TestACredentialRevokedHereIsRefusedWhenVerifiedHere(t *testing.T) {
	s, agent := grantWorld(t)
	said, err := s.issueCapabilityGrant(agent, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(said)
	if rec == nil || rec.RegistrySAID == "" {
		t.Fatalf("the grant was not issued into a registry: %+v", rec)
	}

	live := verifyHere(t, s, rec.AcdcJson)
	if live.RevocationStatus != revocationNotRevoked || live.Checks["not_revoked"] != true {
		t.Fatalf("a live credential issued here reads %q, checks %v", live.RevocationStatus, live.Checks["not_revoked"])
	}

	if _, _, err := s.withdrawCredential(rec); err != nil {
		t.Fatal(err)
	}
	got := verifyHere(t, s, rec.AcdcJson)
	if got.Verified {
		t.Fatal("a credential revoked here still verified")
	}
	if got.RevocationStatus != revocationRevoked || got.Checks["not_revoked"] != false {
		t.Errorf("status %q, not_revoked %v", got.RevocationStatus, got.Checks["not_revoked"])
	}
	if !strings.Contains(strings.Join(got.Errors, "|"), "revoked") || got.RevocationReason == "" {
		t.Errorf("the reply does not say why: errors %v, reason %q", got.Errors, got.RevocationReason)
	}
}

// A credential whose registry this agent does not hold is not called revoked
// or not revoked: the reply says it was not checked, and the verdict on an
// unreachable source is left to the caller.
func TestACredentialFromElsewhereReportsNotChecked(t *testing.T) {
	issuer, agent := grantWorld(t)
	said, err := issuer.issueCapabilityGrant(agent, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := issuer.DataStore.GetCredential(said)

	verifier, _ := grantWorld(t) // a different agent, with a different store
	got := verifyHere(t, verifier, rec.AcdcJson)
	if got.RevocationStatus != revocationNoRegistryState {
		t.Fatalf("status %q, want %q", got.RevocationStatus, revocationNoRegistryState)
	}
	if got.Checks["not_revoked"] == true {
		t.Fatal("a credential from elsewhere was reported as not revoked")
	}
}
