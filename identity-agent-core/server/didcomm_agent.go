package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"identity-agent-core/didcomm"
)

// sendDIDCommMessage packs an authcrypt envelope from a local AID to a registered peer
// and delivers it over direct HTTPS. Shared by the /api/didcomm/send handler and the
// agent auto-responder. Returns the message id and the peer's HTTP status.
func (s *CoreServer) sendDIDCommMessage(fromAID, toAID, typ string, body json.RawMessage) (string, int, error) {
	sender, err := s.keySetFor(fromAID)
	if err != nil {
		return "", 0, fmt.Errorf("sender keyset: %w", err)
	}
	didcommMu.Lock()
	peer, ok := s.loadPeers()[toAID]
	didcommMu.Unlock()
	if !ok {
		// Convenience for intra-org agent-to-agent: if the recipient is one of THIS
		// IA's own provisioned agents, auto-establish the relationship (mint its DID +
		// register it against the loopback /didcomm) so the UI can message between two
		// workforce agents with just from/to/body. Cross-IA peers must be registered
		// explicitly (we can't mint keys for an identity we don't control).
		if p, aerr := s.ensureLocalPeer(toAID); aerr == nil {
			peer = p
		} else {
			return "", 0, fmt.Errorf("no registered peer %s", toAID)
		}
	}
	if peer.Endpoint == "" {
		return "", 0, fmt.Errorf("peer %s has no endpoint", toAID)
	}
	if len(body) == 0 {
		body = json.RawMessage("{}")
	}
	now := time.Now().UTC()
	jwm := &didcomm.JWM{
		ID:          newMessageID(),
		Type:        typ,
		From:        "did:keri:" + fromAID,
		To:          []string{"did:keri:" + toAID},
		CreatedTime: now.Format(time.RFC3339),
		ExpiresTime: now.Add(10 * time.Minute).Format(time.RFC3339),
		Body:        body,
	}
	env, err := didcomm.PackAuthcrypt(sender, &peer.DID, jwm)
	if err != nil {
		return "", 0, fmt.Errorf("pack: %w", err)
	}
	raw, _ := json.Marshal(env)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Post(peer.Endpoint, "application/didcomm-envelope+json", bytes.NewReader(raw))
	if err != nil {
		return jwm.ID, 0, fmt.Errorf("delivery: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return jwm.ID, resp.StatusCode, nil
}

// answerAgentMessage runs when a provisioned agent receives an agent-message (a
// question) over DIDComm. It runs the recipient agent's brain to produce an answer and
// replies with an agent-result — one AI agent answering another, IA-to-IA. Fire-and-
// forget (called in a goroutine); failures are logged, not surfaced to the sender's
// HTTP call (the sender already got its 202 for the inbound question).
func (s *CoreServer) answerAgentMessage(toAID, fromAID string, jwm *didcomm.JWM) {
	var q struct {
		Question string `json:"question"`
		Text     string `json:"text"`
		Prompt   string `json:"prompt"`
	}
	_ = json.Unmarshal(jwm.Body, &q)
	question := firstNonEmpty(q.Question, q.Text, q.Prompt)
	if question == "" {
		log.Printf("[didcomm-agent] %s received an agent-message with no question", toAID)
		return
	}
	answer, model, err := s.runAgentBrain(toAID, question)
	if err != nil {
		log.Printf("[didcomm-agent] %s could not answer: %v", toAID, err)
		answer = fmt.Sprintf("(could not reach my brain: %v)", err)
	}
	reply, _ := json.Marshal(map[string]any{
		"answer":      answer,
		"in_reply_to": jwm.ID,
		"answered_by": toAID,
		"model":       model,
	})
	msgID, status, err := s.sendDIDCommMessage(toAID, fromAID, didcomm.TypeAgentResult, reply)
	if err != nil {
		log.Printf("[didcomm-agent] %s failed to send agent-result: %v", toAID, err)
		return
	}
	log.Printf("[didcomm-agent] %s answered %s (%s → agent-result %s, peer %d)", toAID, fromAID, jwm.ID, msgID, status)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
