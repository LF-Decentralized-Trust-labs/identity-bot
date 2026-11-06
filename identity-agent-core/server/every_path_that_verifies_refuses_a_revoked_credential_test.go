package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"identity-agent-core/drivers"
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

// The credential gate admits a credential only on its bytes. A revoked one is
// refused with its bytes, and one sent without them is refused too: the said
// and status of a declared entry are the holder's own words, so a made-up said
// cannot be used to step round this agent's record of a revocation.
func TestTheLoginGateRefusesARevokedCredentialAndAnyCredentialSentWithoutItsBytes(t *testing.T) {
	s, said, acdc, revoke := issuedThenRevoked(t)
	const schema = "ESchemaTheSiteRequires"
	declared := func(said, body string) []interface{} {
		m := map[string]interface{}{"said": said, "schema_said": schema, "status": "issued"}
		if body != "" {
			m["acdc_json_b64"] = body
		}
		return []interface{}{m}
	}

	revoke()
	for name, presented := range map[string][]interface{}{
		"with bytes":                   declared(said, acdc),
		"no bytes, its real said":      declared(said, ""),
		"no bytes, a made-up said":     declared("EMadeUpByTheHolder", ""),
		"no bytes, no said at all":     declared("", ""),
		"unpadded bytes of the credit": declared(said, strings.TrimRight(acdc, "=")),
	} {
		if ok, reason := s.credentialGateSatisfied(context.Background(), presented, issueeOf(t, acdc), schema, ""); ok {
			t.Errorf("%s: the gate admitted a credential revoked here (%s)", name, reason)
		}
	}
	// And a credential that is not revoked is not admitted on a declared
	// entry either.
	s2, said2, acdc2, _ := issuedThenRevoked(t)
	if ok, _ := s2.credentialGateSatisfied(context.Background(), declared(said2, ""), issueeOf(t, acdc2), schema, ""); ok {
		t.Error("the gate admitted a declared entry with no credential body")
	}
}

// The engine reads base64 in any spelling, so the server must read the same
// credential the engine does. A revoked credential sent unpadded is revoked on
// every path, and one the server cannot read at all is refused rather than
// passed on with no registry to check.
func TestARevokedCredentialInAnyBase64SpellingIsRefused(t *testing.T) {
	s, said, acdc, revoke := issuedThenRevoked(t)
	revoke()
	raw, err := base64.StdEncoding.DecodeString(acdc)
	if err != nil {
		t.Fatal(err)
	}
	spellings := map[string]string{
		"unpadded":     base64.RawStdEncoding.EncodeToString(raw),
		"url alphabet": base64.URLEncoding.EncodeToString(raw),
		"unpadded url": base64.RawURLEncoding.EncodeToString(raw),
	}
	for name, spelled := range spellings {
		got := verifyHere(t, s, spelled)
		if got.Verified || got.RevocationStatus != revocationRevoked {
			t.Errorf("%s: credential/verify read %+v", name, got)
		}
		chain := verifyChainHere(t, s, map[string]any{"acdc_json_b64": spelled})
		if chain.Valid || len(chain.Chain) == 0 || chain.Chain[0].RevocationStatus != revocationRevoked {
			t.Errorf("%s: the chain verifier read %+v", name, chain)
		}
		if ok, _, _ := s.verifyPresentedCredentialACDC(context.Background(), spelled, "", "", "", "", nil); ok {
			t.Errorf("%s: login accepted a credential revoked here", name)
		}
	}
	_ = said
}

func TestACredentialTheServerCannotReadIsRefused(t *testing.T) {
	s, _, _, _ := issuedThenRevoked(t)
	junk := base64.StdEncoding.EncodeToString([]byte(`{"d":"x","i":"y","ri":"z"}`))

	raw, _ := json.Marshal(map[string]any{"acdc_json": junk})
	rec := httptest.NewRecorder()
	s.handleVerifyCredential(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("credential/verify answered %d for a body it cannot read: %s", rec.Code, rec.Body.String())
	}
	for _, body := range []string{junk, "not base64 !!"} {
		chain := verifyChainHere(t, s, map[string]any{"acdc_json_b64": body})
		if chain.Valid || len(chain.Chain) == 0 || chain.Chain[0].Valid {
			t.Errorf("the chain verifier passed an unreadable body: %+v", chain)
		}
		if ok, _, _ := s.verifyPresentedCredentialACDC(context.Background(), body, "", "", "", "", nil); ok {
			t.Error("login accepted an unreadable body")
		}
	}
}

// issueeOf is the identity a credential was issued to: the one that must be
// signing in for the gate to look at it at all.
func issueeOf(t *testing.T, acdcB64 string) string {
	t.Helper()
	cred, err := readCredentialHere(acdcB64)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		A struct {
			I string `json:"i"`
		} `json:"a"`
	}
	if err := json.Unmarshal(cred.Raw, &body); err != nil || body.A.I == "" {
		t.Fatalf("the credential names no issuee: %v", err)
	}
	return body.A.I
}

// A grant being withdrawn (never in force) whose kept log holds only its
// issuance is refused on both verify routes and at login, on this agent's own
// record. Fails if the record stops winning over a log that reads as issued.
func TestAWithdrawingCredentialIsRefusedOnEveryPathWhateverItsLogShows(t *testing.T) {
	s, said, acdc, _ := issuedThenRevoked(t)
	if err := s.DataStore.UpdateCredentialStatus(said, credentialStatusWithdrawing); err != nil {
		t.Fatal(err)
	}
	got := verifyHere(t, s, acdc)
	if got.Verified || got.RevocationStatus != revocationRevoked || got.Checks["not_revoked"] != false || got.RevocationReason == "" {
		t.Errorf("credential/verify read %+v", got)
	}
	chain := verifyChainHere(t, s, map[string]any{"acdc_json_b64": acdc})
	if chain.Valid || len(chain.Chain) == 0 || chain.Chain[0].Valid || chain.Chain[0].RevocationStatus != revocationRevoked {
		t.Errorf("the chain verifier read %+v", chain)
	}
	ok, _, reason := s.verifyPresentedCredentialACDC(context.Background(), acdc, "", "", "", "", nil)
	if ok || !strings.Contains(reason, "recorded the credential as withdrawing") {
		t.Errorf("login: ok=%v reason=%q", ok, reason)
	}
}

// Where the status is "not checked", the reply does not read not_revoked true,
// even if the engine said so.
func TestNotCheckedNeverLeavesNotRevokedTrue(t *testing.T) {
	res := revocationState{status: revocationNoRegistryState}.applyTo(
		&drivers.DriverVerifyCredentialResponse{Checks: map[string]interface{}{"not_revoked": true}})
	v, present := res.Checks["not_revoked"]
	if !present || v != nil {
		t.Fatalf("not_revoked reads %v (present %v), want null", v, present)
	}
}
