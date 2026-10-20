package server

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
	"identity-agent-core/sandbox"
	"identity-agent-core/schemas"

	"github.com/go-chi/chi/v5"
)

// testMachine is a machine with a P-256 key, as secure hardware holds one.
type testMachine struct{ priv *ecdsa.PrivateKey }

func newTestMachine(t *testing.T) testMachine {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testMachine{p}
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
	ks, err := didcomm.GenerateKeySet(host)
	if err != nil {
		t.Fatal(err)
	}
	_, _, x, kem, err := ks.PublicMaterial()
	if err != nil {
		t.Fatal(err)
	}
	return agentbody.Keys{Host: host, Verkey: verkey,
		X25519: base64.RawURLEncoding.EncodeToString(x), MLKEM768: base64.RawURLEncoding.EncodeToString(kem)}
}

// enrolRequest is what the machine sends for an enrolment string.
func (m testMachine) enrolRequest(t *testing.T, enrolment, claimed string) []byte {
	t.Helper()
	e, err := agentbody.ParseEnrolment(enrolment)
	if err != nil {
		t.Fatal(err)
	}
	k := m.keys(t)
	nonce := "nonce-" + strings.Repeat("x", 16)
	sig, err := agentbody.Sign(m, agentbody.EnrolProof(e, nonce, k, claimed, "macos/arm64", "computer"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(bodyEnrolRequest{Secret: e.Secret, Agent: e.Agent, Keys: k, Nonce: nonce,
		ClaimedGrade: claimed, Platform: "macos/arm64", Placement: "computer", Signature: sig})
	return b
}

// signed is a request the machine signs with its key.
func (m testMachine) signed(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	host, _, _ := agentbody.Identity(m)
	ts := time.Now().UTC().Format(time.RFC3339)
	sig, err := agentbody.Sign(m, agentbody.RequestToSign(host, method, path, ts, body))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "203.0.113.9:443"
	r.Header.Set(agentbody.HeaderHost, host)
	r.Header.Set(agentbody.HeaderSignature, sig)
	r.Header.Set(agentbody.HeaderTimestamp, ts)
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
func bodyWorld(t *testing.T) (*CoreServer, string) {
	t.Helper()
	s, agent := grantWorld(t)
	if err := s.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	if err := s.assetHandler.Store.UpsertAsset(*agent); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueCapabilityGrant(agent); err != nil {
		t.Fatal(err)
	}
	mgr, err := sandbox.NewManager(sandbox.ManagerConfig{DataDir: s.DataDir})
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

func (s *CoreServer) testEnrolment(t *testing.T, agentID string) string {
	t.Helper()
	code, out := call(t, s.handleCreateBodyEnrolment, withRoute(httptest.NewRequest("POST", "/", nil), map[string]string{"id": agentID}))
	if code != http.StatusCreated {
		t.Fatalf("issuing an enrolment string: %d %v", code, out)
	}
	return out["enrolment"].(string)
}

// The whole ceremony, as D-050 draws it: a string, a machine enrolling with its
// own key, the same six words on both sides, approval, a body credential, and a
// request signed by the machine taken as the AI agent's — at the body's grade.
func TestAMachineBecomesAnAIAgentsBody(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	enrolment := s.testEnrolment(t, agentID)

	code, out := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/api/agent-host/enrol",
		bytes.NewReader(m.enrolRequest(t, enrolment, agentbody.GradeHardwareAsserted))))
	if code != http.StatusAccepted || out["state"] != agentbody.StatePending {
		t.Fatalf("enrolling: %d %v", code, out)
	}
	host, _, _ := agentbody.Identity(m)
	machineWords := strings.Join(agentbody.Words(host), " ")

	_, list := call(t, s.handleListBodies, withRoute(httptest.NewRequest("GET", "/", nil), map[string]string{"id": agentID}))
	bodies := list["bodies"].([]any)
	shown := bodies[0].(map[string]any)
	if shown["words_line"] != machineWords {
		t.Fatalf("the owner is shown %q, the machine shows %q", shown["words_line"], machineWords)
	}

	code, approved := call(t, s.handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil),
		map[string]string{"id": agentID, "bid": shown["id"].(string)}))
	if code != http.StatusOK || approved["state"] != agentbody.StateActive {
		t.Fatalf("approving: %d %v", code, approved)
	}
	rec, _ := s.DataStore.GetCredential(approved["credential_said"].(string))
	if rec == nil || rec.SchemaSAID != schemas.AIAgentBody.Schema.SAID || rec.Status != "issued" {
		t.Fatalf("no body credential was issued: %+v", rec)
	}

	r := m.signed(t, "POST", "/api/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	cc := s.resolveCaller(r)
	agent, _ := s.aiAgentAsset(agentID)
	if cc.CallerAID != agent.PairwiseAID || cc.BodyHost != host || cc.BodyGrade != agentbody.GradeHardwareAsserted {
		t.Fatalf("the signed request was not taken as the AI agent's, from its body: %+v", cc)
	}
	if len(cc.Scopes) != 2 {
		t.Fatalf("the AI agent's grant should decide its scopes, got %v", cc.Scopes)
	}

	// The same signed request again is a replay.
	if again := s.resolveCaller(withRoute(cloneSigned(r), nil)); len(again.Scopes) != 0 {
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
	enrolment := s.testEnrolment(t, agentID)
	first, second := newTestMachine(t), newTestMachine(t)
	if code, out := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(first.enrolRequest(t, enrolment, "software")))); code != http.StatusAccepted {
		t.Fatalf("first: %d %v", code, out)
	}
	if code, _ := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(second.enrolRequest(t, enrolment, "software")))); code != http.StatusForbidden {
		t.Fatalf("a reused enrolment string gave %d", code)
	}
}

// A machine that claims more than anything has checked is recorded at the most
// its own report supports, and the clamp is recorded.
func TestABodyCannotAwardItselfAGrade(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	code, out := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(
		m.enrolRequest(t, s.testEnrolment(t, agentID), agentbody.GradeAttestedRuntime))))
	if code != http.StatusAccepted || out["grade"] != agentbody.GradeHardwareAsserted || out["grade_clamped"] != true {
		t.Fatalf("an attested claim with no evidence was recorded as %v (clamped %v)", out["grade"], out["grade_clamped"])
	}
}

// An enrolment signed by one key but offering another is refused: proof of
// possession.
func TestAnEnrolmentMustBeSignedByTheKeyItOffers(t *testing.T) {
	s, agentID := bodyWorld(t)
	m, other := newTestMachine(t), newTestMachine(t)
	var req bodyEnrolRequest
	_ = json.Unmarshal(m.enrolRequest(t, s.testEnrolment(t, agentID), "software"), &req)
	req.Keys = other.keys(t)
	b, _ := json.Marshal(req)
	if code, _ := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(b))); code != http.StatusForbidden {
		t.Fatalf("an enrolment offering a key it did not sign with gave %d", code)
	}
}

// Rejecting — the words did not match — leaves nothing live, and hands back a
// fresh string for the real machine.
func TestRejectingABodyGivesAFreshString(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	old := s.testEnrolment(t, agentID)
	_, out := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, old, "software"))))
	code, rej := call(t, s.handleRejectBody, withRoute(httptest.NewRequest("POST", "/", nil),
		map[string]string{"id": agentID, "bid": out["binding_id"].(string)}))
	if code != http.StatusOK || rej["enrolment"] == "" || rej["enrolment"] == old {
		t.Fatalf("rejecting: %d %v", code, rej)
	}
	if r := s.resolveCaller(m.signed(t, "POST", "/api/mcp", []byte("{}"))); len(r.Scopes) != 0 {
		t.Fatal("a rejected machine was admitted")
	}
	// The rejected machine's key may try again with the fresh string.
	if code, _ := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, rej["enrolment"].(string), "software")))); code != http.StatusAccepted {
		t.Fatalf("the fresh string did not work: %d", code)
	}
}

// Revoking a body stops that machine speaking as the AI agent, and writes the
// revocation to the registry.
func TestARevokedBodyIsRefused(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	_, out := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, s.testEnrolment(t, agentID), "software"))))
	bid := out["binding_id"].(string)
	_, approved := call(t, s.handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil), map[string]string{"id": agentID, "bid": bid}))
	code, rev := call(t, s.handleRevokeBody, withRoute(httptest.NewRequest("DELETE", "/", nil), map[string]string{"id": agentID, "bid": bid}))
	if code != http.StatusOK || rev["tel_revoked"] != true {
		t.Fatalf("revoking: %d %v", code, rev)
	}
	if rec, _ := s.DataStore.GetCredential(approved["credential_said"].(string)); rec == nil || rec.Status != "revoked" {
		t.Fatalf("the body credential is %+v", rec)
	}
	if r := s.resolveCaller(m.signed(t, "POST", "/api/mcp", []byte("{}"))); len(r.Scopes) != 0 || r.BodyHost != "" {
		t.Fatal("a revoked body was admitted")
	}
}

// Through the real router: the gate admits a body-signed request and hands the
// caller it resolved to the handler. Resolving again would spend the body's
// signature a second time and refuse the request just admitted.
func TestABodySignedRequestPassesTheGateOnce(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	_, out := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/", bytes.NewReader(m.enrolRequest(t, s.testEnrolment(t, agentID), "software"))))
	call(t, s.handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil), map[string]string{"id": agentID, "bid": out["binding_id"].(string)}))

	router := s.buildRouter("")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, m.signed(t, "POST", "/api/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	// The capabilities offered depend on the caller the handler sees. An
	// anonymous caller — what a second, refused resolution would leave — is
	// offered none of the AI agent's.
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"system.info.read"`) {
		t.Fatalf("a body-signed request through the router: %d %s", w.Code, w.Body.String())
	}

	// And the machine can ask whether it was approved, signed by its own key.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, m.signed(t, "GET", "/api/agent-host/binding", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"active"`) {
		t.Fatalf("the machine's status check: %d %s", w.Code, w.Body.String())
	}
}
