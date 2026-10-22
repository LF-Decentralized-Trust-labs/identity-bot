package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/keriengine"
	"identity-agent-core/sandbox"
)

func logWorld(t *testing.T) *CoreServer {
	t.Helper()
	s := agentWithDerivedIdentity(t)
	s.KeriDriver = keriengine.New()
	m, err := sandbox.NewManager(sandbox.ManagerConfig{DataDir: s.DataDir, ManifestsDir: t.TempDir()})
	if err != nil {
		t.Skipf("sandbox manager unavailable: %v", err)
	}
	s.SandboxManager = m
	m.SetEventSigner(&invocationSigner{s: s})
	return s
}

func askChain(t *testing.T, s *CoreServer) map[string]any {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/activity/chain", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	s.handleVerifyAuditChain(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// The log this agent writes, signed by its own log signer, verifies on its
// signatures as well as its links; a row rewritten with every link after it
// re-made does not.
func TestTheLogIsCheckedOnItsSignatures(t *testing.T) {
	s := logWorld(t)
	caller := sandbox.CallerContext{CallerAID: "EAgent", Reason: "test"}
	for _, id := range []string{"ai_agent.body.requested", "ai_agent.body.approved"} {
		if s.SandboxManager.RecordGovernanceEvent(caller, id, "ok") == 0 {
			t.Fatal("event not written")
		}
	}
	if got := askChain(t, s); got["intact"] != true {
		t.Fatalf("the agent's own log does not verify: %v", got)
	}

	// Rewrite the first row and re-link the second, as somebody with the
	// database but not the signer's key would.
	db := s.SandboxManager.Store().DB()
	var id1, id2 int64
	var j1, j2 string
	db.QueryRow(`SELECT id, event_json FROM invocation_log ORDER BY id ASC LIMIT 1`).Scan(&id1, &j1)
	db.QueryRow(`SELECT id, event_json FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&id2, &j2)
	var e1, e2 sandbox.InvocationEvent
	json.Unmarshal([]byte(j1), &e1)
	json.Unmarshal([]byte(j2), &e2)
	e1.ResultStatus = "denied"
	b1, _ := json.Marshal(e1)
	e2.PrevHash = sandbox.HashRecord(b1)
	b2, _ := json.Marshal(e2)
	db.Exec(`UPDATE invocation_log SET event_json = ? WHERE id = ?`, string(b1), id1)
	db.Exec(`UPDATE invocation_log SET event_json = ? WHERE id = ?`, string(b2), id2)

	got := askChain(t, s)
	if got["intact"] != false || got["broken_at"] != float64(id1) {
		t.Fatalf("a re-linked rewrite was not caught at the rewritten row: %v", got)
	}
}

// Checking the log never creates a signer: a log with no signer stays one.
func TestCheckingTheLogNeverMintsASigner(t *testing.T) {
	s := logWorld(t)
	if _, err := s.invocationSignerKey("EAnyone"); err == nil {
		t.Fatal("a key was found for a signer this agent never had")
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, "invocation_signer.json")); !os.IsNotExist(err) {
		t.Fatalf("looking up a key created a signer: %v", err)
	}
}

// Where the signed chain begins is kept in the signer's own file, outside the
// database the log lives in, from the first event this agent signs.
func TestTheChainStartIsKeptOutsideTheDatabase(t *testing.T) {
	s := logWorld(t)
	if s.SandboxManager.RecordGovernanceEvent(sandbox.CallerContext{CallerAID: "EAgent"}, "ai_agent.body.requested", "ok") == 0 {
		t.Fatal("event not written")
	}
	rec, found, err := readInvocationSignerRecord(s.DataDir)
	if err != nil || !found || rec.ChainStart == nil || rec.ChainStart.ID != 1 || !rec.ChainStart.Linked {
		t.Fatalf("the chain start was not kept with the signer: %+v found=%v err=%v", rec.ChainStart, found, err)
	}
	if got := askChain(t, s); got["chain_start_kept"] != true || got["intact"] != true {
		t.Fatalf("the check did not use the kept start: %v", got)
	}
}

// A log that cannot be checked is reported as that, never as forged.
func TestALogThatCannotBeCheckedIsNotCalledForged(t *testing.T) {
	s := logWorld(t)
	if s.SandboxManager.RecordGovernanceEvent(sandbox.CallerContext{CallerAID: "EAgent"}, "ai_agent.body.requested", "ok") == 0 {
		t.Fatal("event not written")
	}
	// The key cannot be derived without the root seed.
	os.RemoveAll(filepath.Join(s.DataDir, "secureenclave"))
	req := httptest.NewRequest("GET", "/api/activity/chain", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	s.handleVerifyAuditChain(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(body, "forged") {
		t.Fatalf("an uncheckable log was reported as %d: %s", rec.Code, body)
	}
}
