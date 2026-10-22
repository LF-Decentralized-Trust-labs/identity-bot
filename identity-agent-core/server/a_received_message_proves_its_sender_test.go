package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/sandbox"
	"identity-agent-core/store"
)

// withLog gives a test agent a store and a signed log.
func withLog(t *testing.T, s *CoreServer) {
	t.Helper()
	ds, err := store.NewSQLiteStore(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	s.DataStore = ds
	m, err := sandbox.NewManager(sandbox.ManagerConfig{DataDir: s.DataDir, ManifestsDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	s.SandboxManager = m
}

func logged(t *testing.T, s *CoreServer, event, messageID string) []sandbox.InvocationEvent {
	t.Helper()
	rows, err := s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
		CapabilityID: event, CorrelationID: messageID})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// A message one agent sends another is kept with the sender's signature, so it
// can be shown later to have come from the sender; and both ends write it to
// their signed logs, the receiver's refusal of a replay included.
func TestAReceivedMessageIsKeptWithItsProofAndBothEndsLogIt(t *testing.T) {
	sender, senderAID, receiver, receiverAID := twoAgents(t)
	withLog(t, sender)
	withLog(t, receiver)

	var envelopes [][]byte
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		envelopes = append(envelopes, raw)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		receiver.handleDIDCommInbound(w, r)
	}))
	defer peerSrv.Close()
	didcommMu.Lock()
	peers := sender.loadPeers()
	p := peers[receiverAID]
	p.Endpoint = peerSrv.URL
	peers[receiverAID] = p
	_ = sender.savePeers(peers)
	didcommMu.Unlock()

	msgID, status, err := sender.SendDIDCommMessage(senderAID, receiverAID, didcomm.TypeNotification,
		[]byte(`{"title":"the build passed"}`))
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("send: %d %v", status, err)
	}

	n, err := receiver.DataStore.GetNotification(msgID)
	if err != nil || n == nil {
		t.Fatalf("the message was not kept: %v", err)
	}
	if _, err := provedSender(*n); err != nil {
		t.Fatalf("the kept message does not prove its sender: %v", err)
	}
	altered := *n
	altered.Payload = `{"title":"the build failed"}`
	if _, err := provedSender(altered); err == nil {
		t.Fatal("a kept message whose words were changed still proved its sender")
	}
	unsigned := *n
	unsigned.SignedMessage = ""
	if _, err := provedSender(unsigned); err == nil {
		t.Fatal("a message kept without its signed form was taken as proved")
	}

	if len(logged(t, sender, "didcomm.message.sent", msgID)) != 1 {
		t.Fatal("the sender's log does not record the message it sent")
	}
	if rows := logged(t, receiver, "didcomm.message.received", msgID); len(rows) != 1 || rows[0].ResultStatus != "ok" {
		t.Fatalf("the receiver's log does not record the message it took: %+v", rows)
	}

	// The same envelope again is a replay, refused and recorded as refused,
	// once however many times it is sent.
	for i := 0; i < 3; i++ {
		resp, err := http.Post(peerSrv.URL, "application/json", bytes.NewReader(envelopes[0]))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("a replay was not refused: %d", resp.StatusCode)
		}
	}
	var denied int
	for _, r := range logged(t, receiver, "didcomm.message.received", msgID) {
		if r.ResultStatus == "denied" {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("the refused replay is in the receiver's log %d times; want once", denied)
	}
}
