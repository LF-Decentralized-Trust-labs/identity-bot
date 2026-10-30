package aiagents

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agenthost"
	"identity-agent-core/server"
)

// approvalRequestString builds the self-verifying approval string a machine
// shows for a person to capture, exactly as agent-host does.
func (m testMachine) approvalRequestString(t *testing.T, ia, agent string) string {
	t.Helper()
	host, verkey, err := agentbody.Identity(m)
	if err != nil {
		t.Fatal(err)
	}
	nb := make([]byte, 18)
	if _, err := rand.Read(nb); err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	sig, err := agentbody.Sign(m, agentbody.ApprovalProof(ia, agent, host, verkey, nonce))
	if err != nil {
		t.Fatal(err)
	}
	str, err := agentbody.ApprovalRequest{
		IdentityAgent: ia, Agent: agent, Host: host, Verkey: verkey, Nonce: nonce, Signature: sig,
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return str
}

func decodeRequest(t *testing.T, s *server.CoreServer, agentID, request string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"request": request})
	return call(t, of(s).handleDecodeBodyRequest,
		withRoute(httptest.NewRequest("POST", "/", bytes.NewReader(body)), map[string]string{"id": agentID}))
}

// A person approves a machine by capturing its own signed request — pasted or
// scanned — instead of comparing six words: the Identity Agent verifies the
// signature, finds the pending binding for that key, and the person approves it.
func TestAMachineIsApprovedByItsSignedRequest(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	if code, _ := call(t, of(s).handleBodyEnrol, httptest.NewRequest("POST", "/",
		bytes.NewReader(m.enrolRequest(t, s, of(s).testEnrolment(t, agentID), "software")))); code != http.StatusAccepted {
		t.Fatalf("enrolling: %d", code)
	}
	ia, err := hostOf(s).WhoThisIdentityAgentIs()
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := of(s).aiAgentAsset(agentID)

	// The request the machine showed decodes to the pending binding it is waiting on.
	code, out := decodeRequest(t, s, agentID, m.approvalRequestString(t, ia, agent.PairwiseAID))
	if code != http.StatusOK || out["binding_id"] == nil {
		t.Fatalf("decoding the request: %d %v", code, out)
	}

	// Approving that binding issues the body credential, as before.
	code, approved := call(t, of(s).handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil),
		map[string]string{"id": agentID, "bid": out["binding_id"].(string)}))
	if code != http.StatusOK || approved["state"] != agentbody.StateActive {
		t.Fatalf("approving: %d %v", code, approved)
	}

	// A request for a key that never asked here — the thief's machine, elsewhere —
	// matches no pending binding, so there is nothing for the person to approve.
	if code, _ := decodeRequest(t, s, agentID, newTestMachine(t).approvalRequestString(t, ia, agent.PairwiseAID)); code != http.StatusNotFound {
		t.Fatalf("a request for a key with no pending binding gave %d, not 404", code)
	}

	// A tampered request — another key spliced in over a real signature — fails
	// the signature check.
	tampered, _ := agentbody.ParseApprovalRequest(newTestMachine(t).approvalRequestString(t, ia, agent.PairwiseAID))
	tampered.Host, tampered.Verkey, _ = agentbody.Identity(m)
	str, _ := tampered.Encode()
	if code, _ := decodeRequest(t, s, agentID, str); code == http.StatusOK {
		t.Fatal("a tampered approval request was accepted")
	}
}

// safeBuf is a concurrency-safe writer: agent-host writes to it on one goroutine
// while the test reads it on another to capture what the program printed.
type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// extractApprovalRequest pulls the iaapprove1.… string out of what agent-host
// printed, as a person copying it off the machine's screen would.
func extractApprovalRequest(printed string) string {
	i := strings.Index(printed, agentbody.ApprovalPrefix)
	if i < 0 {
		return ""
	}
	fields := strings.FieldsFunc(printed[i:], func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r'
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// The whole new path with the real program over HTTP: agent-host enrols against
// a running Identity Agent and prints a signed approval request; a person
// captures it (here, read from what the program printed) and the Identity Agent
// verifies it and approves — no six words compared by anyone.
func TestAgentHostIsApprovedByItsSignedRequestEndToEnd(t *testing.T) {
	s, agentID := bodyWorld(t)
	fixtures.RebuildRouter(s)
	srv := httptest.NewServer(hostOf(s).Router())
	defer srv.Close()
	t.Setenv("PUBLIC_URL", srv.URL)

	m := newTestMachine(t)
	out := &safeBuf{}
	h := &agenthost.Host{DataDir: t.TempDir(), Signer: m, Hardware: true, PollEvery: 20 * time.Millisecond, Out: out}

	enrolment := enrolmentVia(t, s, srv.URL, agentID)

	// As a person would: take the request the machine printed, paste it in, and
	// approve what it decodes to — all while agent-host waits for the decision.
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 300; i++ {
			if req := extractApprovalRequest(out.String()); req != "" {
				body, _ := json.Marshal(map[string]string{"request": req})
				rec := httptest.NewRecorder()
				of(s).handleDecodeBodyRequest(rec, withRoute(
					httptest.NewRequest("POST", "/", bytes.NewReader(body)),
					map[string]string{"id": agentID}))
				var dec map[string]any
				_ = json.Unmarshal(rec.Body.Bytes(), &dec)
				bid, _ := dec["binding_id"].(string)
				if bid == "" {
					done <- fmt.Errorf("the printed request did not decode to a binding: %s", rec.Body.String())
					return
				}
				of(s).handleApproveBody(httptest.NewRecorder(), withRoute(
					httptest.NewRequest("POST", "/", nil),
					map[string]string{"id": agentID, "bid": bid}))
				done <- nil
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		done <- fmt.Errorf("agent-host never printed an approval request: %q", out.String())
	}()

	st, err := h.Enrol(enrolment, "computer", 20*time.Second)
	if derr := <-done; derr != nil {
		t.Fatal(derr)
	}
	if err != nil {
		t.Fatalf("enrolling: %v", err)
	}
	if st.BindingID == "" {
		t.Fatal("no binding was recorded")
	}

	status, err := h.Status()
	if err != nil || status["state"] != agentbody.StateActive {
		t.Fatalf("after approval by its signed request, status: %v %v", status, err)
	}
}
