package aiagents

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/sandbox"
	"identity-agent-core/schemas"
	"identity-agent-core/server"

	"github.com/go-chi/chi/v5"
)

// testMachine is a machine with a P-256 key, as secure hardware holds one, and
// the software sealing keys every body has beside it.
type testMachine struct {
	priv *ecdsa.PrivateKey
	ks   *didcomm.KeySet
}

func newTestMachine(t *testing.T) testMachine {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := testMachine{priv: p}
	host, _, _ := agentbody.Identity(m)
	if m.ks, err = didcomm.GenerateKeySet(host); err != nil {
		t.Fatal(err)
	}
	return m
}
func (m testMachine) PublicKey() ([]byte, error) {
	return elliptic.MarshalCompressed(elliptic.P256(), m.priv.X, m.priv.Y), nil
}
func (m testMachine) Sign(d []byte) ([]byte, error) {
	sum := sha256.Sum256(d)
	r, s, err := ecdsa.Sign(rand.Reader, m.priv, sum[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

func (m testMachine) keys(t *testing.T) agentbody.Keys {
	t.Helper()
	host, verkey, err := agentbody.Identity(m)
	if err != nil {
		t.Fatal(err)
	}
	k, err := agentbody.KeysFrom(host, verkey, m.ks)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// enrolRequest is what the machine sends for an enrolment string: sealed to
// the Identity Agent, signed by the machine's key.
func (m testMachine) enrolRequest(t *testing.T, s *server.CoreServer, enrolment, claimed string) []byte {
	return sealedEnrolment(t, s, m, m, enrolment, claimed)
}

// sealedEnrolment signs as signer and offers (and seals from) offered's keys.
func sealedEnrolment(t *testing.T, s *server.CoreServer, signer, offered testMachine, enrolment, claimed string) []byte {
	t.Helper()
	e, err := agentbody.ParseEnrolment(enrolment)
	if err != nil {
		t.Fatal(err)
	}
	k := offered.keys(t)
	nonce := "nonce-" + strings.Repeat("x", 16)
	sig, err := agentbody.Sign(signer, agentbody.EnrolProof(e, nonce, k, claimed, "macos/arm64", "computer"))
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := json.Marshal(agentbody.EnrolRequest{Secret: e.Secret, Agent: e.Agent, Keys: k, Nonce: nonce,
		ClaimedGrade: claimed, Platform: "macos/arm64", Placement: "computer", Signature: sig})
	iaKS, err := hostOf(s).KeySetFor(e.IdentityAgent)
	if err != nil {
		t.Fatal(err)
	}
	iaDID, _ := iaKS.DID()
	env, err := didcomm.PackAuthcrypt(offered.ks, iaDID, &didcomm.JWM{ID: nonce, Type: didcomm.TypeBodyEnrolment,
		From: "did:keri:" + k.Host, To: []string{"did:keri:" + e.IdentityAgent}, Body: inner})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(agentbody.SealedEnrolment{Sender: k, Envelope: env})
	return b
}

// signed is a request the machine signs with its key, for the Identity Agent s.
func (m testMachine) signed(t *testing.T, s *server.CoreServer, method, target string, body []byte) *http.Request {
	t.Helper()
	host, _, _ := agentbody.Identity(m)
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := "nonce-" + base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	ia := hostOf(s).ThisIdentityAgentsIdentifier()
	sig, err := agentbody.Sign(m, agentbody.SignedRequest{For: ia, Host: host, Method: method, Target: r.URL.RequestURI(),
		Timestamp: ts, Nonce: nonce, Body: body}.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = "203.0.113.9:443"
	r.Header.Set(agentbody.HeaderHost, host)
	r.Header.Set(agentbody.HeaderSignature, sig)
	r.Header.Set(agentbody.HeaderTimestamp, ts)
	r.Header.Set(agentbody.HeaderNonce, nonce)
	r.Header.Set(agentbody.HeaderFor, ia)
	return r
}

func withRoute(r *http.Request, params map[string]string) *http.Request {
	rc := chi.NewRouteContext()
	for k, v := range params {
		rc.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

func call(t *testing.T, h http.HandlerFunc, r *http.Request) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// bodyWorld is an organisation with an AI agent holding a grant, ready for a
// machine to become its body.
func bodyWorld(t *testing.T) (*server.CoreServer, string) {
	t.Helper()
	s, agent := helpers.GrantWorld(t)
	if err := hostOf(s).InitAssetHandler(); err != nil {
		t.Fatal(err)
	}
	if err := hostOf(s).AssetHandler().Store.UpsertAsset(*agent); err != nil {
		t.Fatal(err)
	}
	if _, err := hostOf(s).IssueCapabilityGrant(agent, coretypes.Authority{}); err != nil {
		t.Fatal(err)
	}
	mgr, err := sandbox.NewManager(sandbox.ManagerConfig{Log: hostOf(s).LogForTest(t, s.DataDir), Vault: hostOf(s).VaultForTest(s.DataDir), DataDir: s.DataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Stop)
	s.SandboxManager = mgr
	if err := mgr.Store().UpsertCapabilityRecord(sandbox.CapabilityRecord{
		ID: "system.info.read", Name: "Read system information", Domain: "system",
		ExecutorType: "external_api", Provider: "registry-native", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	return s, agent.ID
}

func (s *aiAgents) testEnrolment(t *testing.T, agentID string) string {
	t.Helper()
	code, out := call(t, s.handleCreateBodyEnrolment, withRoute(httptest.NewRequest("POST", "/", nil), map[string]string{"id": agentID}))
	if code != http.StatusCreated {
		t.Fatalf("issuing an enrolment string: %d %v", code, out)
	}
	return out["enrolment"].(string)
}

// The whole ceremony: a string, a machine enrolling with its
// own key, the same six words on both sides, approval, a body credential, and a
// request signed by the machine taken as the AI agent's — at the body's grade.
func TestAMachineBecomesAnAIAgentsBody(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	enrolment := of(s).testEnrolment(t, agentID)

	code, out := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/api/agent-host/enrol",
		bytes.NewReader(m.enrolRequest(t, s, enrolment, agentbody.GradeHardwareAsserted))))
	if code != http.StatusAccepted || out["state"] != agentbody.StatePending {
		t.Fatalf("enrolling: %d %v", code, out)
	}
	host, _, _ := agentbody.Identity(m)
	machineWords := strings.Join(agentbody.Words(host), " ")

	_, list := call(t, of(s).handleListBodies, withRoute(httptest.NewRequest("GET", "/", nil), map[string]string{"id": agentID}))
	bodies := list["bodies"].([]any)
	shown := bodies[0].(map[string]any)
	if shown["words_line"] != machineWords {
		t.Fatalf("the owner is shown %q, the machine shows %q", shown["words_line"], machineWords)
	}

	code, approved := call(t, of(s).handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil),
		map[string]string{"id": agentID, "bid": shown["id"].(string)}))
	if code != http.StatusOK || approved["state"] != agentbody.StateActive {
		t.Fatalf("approving: %d %v", code, approved)
	}
	rec, _ := s.DataStore.GetCredential(approved["credential_said"].(string))
	if rec == nil || rec.SchemaSAID != schemas.AIAgentBody.Schema.SAID || rec.Status != "issued" {
		t.Fatalf("no body credential was issued: %+v", rec)
	}

	r := m.signed(t, s, "POST", "/api/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	cc := hostOf(s).ResolveCaller(r)
	agent, _ := of(s).aiAgentAsset(agentID)
	if cc.CallerAID != agent.PairwiseAID || cc.BodyHost != host || cc.BodyGrade != agentbody.GradeHardwareAsserted {
		t.Fatalf("the signed request was not taken as the AI agent's, from its body: %+v", cc)
	}
	if len(cc.Scopes) != 2 {
		t.Fatalf("the AI agent's grant should decide its scopes, got %v", cc.Scopes)
	}

	// The same signed request again is a replay.
	if again := hostOf(s).ResolveCaller(withRoute(cloneSigned(r), nil)); len(again.Scopes) != 0 {
		t.Fatal("a replayed signed request was admitted")
	}
}

func cloneSigned(r *http.Request) *http.Request {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	c := httptest.NewRequest(r.Method, r.URL.Path, bytes.NewReader(body))
	c.RemoteAddr = r.RemoteAddr
	c.Header = r.Header.Clone()
	return c
}

// A secret works once: a second machine using it is refused.
func TestAnEnrolmentStringWorksOnce(t *testing.T) {
	s, agentID := bodyWorld(t)
	enrolment := of(s).testEnrolment(t, agentID)
	first, second := newTestMachine(t), newTestMachine(t)
	if code, out := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(first.enrolRequest(t, s, enrolment, "software")))); code != http.StatusAccepted {
		t.Fatalf("first: %d %v", code, out)
	}
	if code, _ := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(second.enrolRequest(t, s, enrolment, "software")))); code != http.StatusForbidden {
		t.Fatalf("a reused enrolment string gave %d", code)
	}
}

// A machine that claims more than anything has checked is recorded at the most
// its own report supports, and the clamp is recorded.
func TestABodyCannotAwardItselfAGrade(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	code, out := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(
		m.enrolRequest(t, s, of(s).testEnrolment(t, agentID), agentbody.GradeAttestedRuntime))))
	if code != http.StatusAccepted || out["grade"] != agentbody.GradeHardwareAsserted || out["grade_clamped"] != true {
		t.Fatalf("an attested claim with no evidence was recorded as %v (clamped %v)", out["grade"], out["grade_clamped"])
	}
}

// An enrolment signed by one key but offering another is refused: proof of
// possession.
func TestAnEnrolmentMustBeSignedByTheKeyItOffers(t *testing.T) {
	s, agentID := bodyWorld(t)
	m, other := newTestMachine(t), newTestMachine(t)
	b := sealedEnrolment(t, s, m, other, of(s).testEnrolment(t, agentID), "software")
	if code, _ := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(b))); code != http.StatusForbidden {
		t.Fatalf("an enrolment offering a key it did not sign with gave %d", code)
	}
}

// The enrolment carries a one-time secret and the machine's keys, so it must
// arrive sealed to this Identity Agent; one sent in the clear is refused.
func TestAnUnsealedEnrolmentIsRefused(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	e, _ := agentbody.ParseEnrolment(of(s).testEnrolment(t, agentID))
	plain, _ := json.Marshal(map[string]any{"secret": e.Secret, "agent": e.Agent, "keys": m.keys(t)})
	if code, _ := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(plain))); code != http.StatusBadRequest {
		t.Fatalf("an unsealed enrolment gave %d", code)
	}
	if len(of(s).bodies().ForAgent(agentID)) != 0 {
		t.Fatal("an unsealed enrolment was recorded")
	}
}

// Rejecting — the words did not match — leaves nothing live, and hands back a
// fresh string for the real machine.
func TestRejectingABodyGivesAFreshString(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	old := of(s).testEnrolment(t, agentID)
	_, out := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, s, old, "software"))))
	code, rej := call(t, of(s).handleRejectBody, withRoute(httptest.NewRequest("POST", "/", nil),
		map[string]string{"id": agentID, "bid": out["binding_id"].(string)}))
	if code != http.StatusOK || rej["enrolment"] == "" || rej["enrolment"] == old {
		t.Fatalf("rejecting: %d %v", code, rej)
	}
	if r := hostOf(s).ResolveCaller(m.signed(t, s, "POST", "/api/mcp", []byte("{}"))); len(r.Scopes) != 0 {
		t.Fatal("a rejected machine was admitted")
	}
	// The rejected machine's key may try again with the fresh string.
	if code, _ := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, s, rej["enrolment"].(string), "software")))); code != http.StatusAccepted {
		t.Fatalf("the fresh string did not work: %d", code)
	}
}

// Revoking a body stops that machine speaking as the AI agent, and writes the
// revocation to the registry.
func TestARevokedBodyIsRefused(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	_, out := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, s, of(s).testEnrolment(t, agentID), "software"))))
	bid := out["binding_id"].(string)
	_, approved := call(t, of(s).handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil), map[string]string{"id": agentID, "bid": bid}))
	code, rev := call(t, of(s).handleRevokeBody, withRoute(httptest.NewRequest("DELETE", "/", nil), map[string]string{"id": agentID, "bid": bid}))
	if code != http.StatusOK || rev["tel_revoked"] != true {
		t.Fatalf("revoking: %d %v", code, rev)
	}
	if rec, _ := s.DataStore.GetCredential(approved["credential_said"].(string)); rec == nil || rec.Status != "revoked" {
		t.Fatalf("the body credential is %+v", rec)
	}
	if r := hostOf(s).ResolveCaller(m.signed(t, s, "POST", "/api/mcp", []byte("{}"))); len(r.Scopes) != 0 || r.BodyHost != "" {
		t.Fatal("a revoked body was admitted")
	}
}

// Through the real router: the gate admits a body-signed request and hands the
// caller it resolved to the handler. Resolving again would spend the body's
// signature a second time and refuse the request just admitted.
func TestABodySignedRequestPassesTheGateOnce(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	_, out := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, s, of(s).testEnrolment(t, agentID), "software"))))
	call(t, of(s).handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil), map[string]string{"id": agentID, "bid": out["binding_id"].(string)}))

	router := hostOf(s).BuildRouter("")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, m.signed(t, s, "POST", "/api/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	// The capabilities offered depend on the caller the handler sees. An
	// anonymous caller — what a second, refused resolution would leave — is
	// offered none of the AI agent's.
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"system.info.read"`) {
		t.Fatalf("a body-signed request through the router: %d %s", w.Code, w.Body.String())
	}

	// And the machine can ask whether it was approved, signed by its own key.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, m.signed(t, s, "GET", "/api/agent-host/binding", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"active"`) {
		t.Fatalf("the machine's status check: %d %s", w.Code, w.Body.String())
	}
}

// A relay that can read TLS must not be able to change what a body asked for:
// the query, or the purpose the record will state, are inside the signature.
func TestARelayCannotChangeWhatABodySigned(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	_, out := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, s, of(s).testEnrolment(t, agentID), "software"))))
	call(t, of(s).handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil), map[string]string{"id": agentID, "bid": out["binding_id"].(string)}))

	for name, tamper := range map[string]func(*http.Request){
		"the query":   func(r *http.Request) { r.URL.RawQuery = "limit=1000" },
		"the purpose": func(r *http.Request) { r.Header.Set(agentbody.HeaderReason, "something else") },
		"the path":    func(r *http.Request) { r.URL.Path, r.URL.RawPath = "/api/mcp/x", "" },
	} {
		r := m.signed(t, s, "POST", "/api/mcp?limit=1", []byte(`{}`))
		tamper(r)
		if cc := hostOf(s).ResolveCaller(r); len(cc.Scopes) != 0 {
			t.Fatalf("changing %s after signing was not noticed", name)
		}
	}
	if cc := hostOf(s).ResolveCaller(m.signed(t, s, "POST", "/api/mcp?limit=1", []byte(`{}`))); len(cc.Scopes) == 0 {
		t.Fatal("an untouched signed request with a query was refused")
	}
}

// A request nobody decided on before its string ran out cannot be approved.
func TestAnExpiredRequestCannotBeApproved(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	_, out := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, s, of(s).testEnrolment(t, agentID), "software"))))
	bid := out["binding_id"].(string)
	b, _ := of(s).bodies().Get(bid)
	// Wind the request's window into the past, as fifteen minutes would.
	if _, err := of(s).bodies().Decide(bid, agentID, agentbody.StateActive, "x", "", b.PendingUntil.Add(time.Second)); err == nil {
		t.Fatal("an expired request was approved")
	}
}
