package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/agentbody"
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

func decodeRequest(t *testing.T, s *CoreServer, agentID, request string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"request": request})
	return call(t, s.handleDecodeBodyRequest,
		withRoute(httptest.NewRequest("POST", "/", bytes.NewReader(body)), map[string]string{"id": agentID}))
}

// A person approves a machine by capturing its own signed request — pasted or
// scanned — instead of comparing six words: the Identity Agent verifies the
// signature, finds the pending binding for that key, and the person approves it.
func TestAMachineIsApprovedByItsSignedRequest(t *testing.T) {
	s, agentID := bodyWorld(t)
	m := newTestMachine(t)
	if code, _ := call(t, s.handleBodyEnrol, httptest.NewRequest("POST", "/",
		bytes.NewReader(m.enrolRequest(t, s, s.testEnrolment(t, agentID), "software")))); code != http.StatusAccepted {
		t.Fatalf("enrolling: %d", code)
	}
	ia, err := s.whoThisIdentityAgentIs()
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := s.aiAgentAsset(agentID)

	// The request the machine showed decodes to the pending binding it is waiting on.
	code, out := decodeRequest(t, s, agentID, m.approvalRequestString(t, ia, agent.PairwiseAID))
	if code != http.StatusOK || out["binding_id"] == nil {
		t.Fatalf("decoding the request: %d %v", code, out)
	}

	// Approving that binding issues the body credential, as before.
	code, approved := call(t, s.handleApproveBody, withRoute(httptest.NewRequest("POST", "/", nil),
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
