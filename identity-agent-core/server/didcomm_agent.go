package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/permission"
)

// SendDIDCommMessage packs an authcrypt envelope from a local AID to a registered peer
// and delivers it over direct HTTPS. Exported so an overlay (or the /api/didcomm/send
// handler) can send messages — including an agent's reply — as the local AID. Returns
// the message id and the peer's HTTP status.
func (s *CoreServer) SendDIDCommMessage(fromAID, toAID, typ string, body json.RawMessage) (string, int, error) {
	sender, err := s.keySetFor(fromAID)
	if err != nil {
		return "", 0, fmt.Errorf("sender keyset: %w", err)
	}
	didcommMu.Lock()
	peer, ok := s.loadPeers()[toAID]
	didcommMu.Unlock()
	if !ok {
		// Intra-org convenience: if the recipient is one of this IA's own provisioned
		// agents, auto-establish the relationship. Cross-IA peers must be registered.
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
	// A request to connect carries our realm, so a peer in the other realm
	// refuses it. Stamped here, where the type is known, so every connect
	// request is tagged regardless of which code built the body — the same
	// reason the key history is attached by type below.
	if typ == didcomm.TypeContactRequest {
		body = withRealm(body)
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

	// A request to connect carries our own key history, because the recipient
	// by definition has no record of us and cannot otherwise open the envelope.
	//
	// Only on this message type. It is a few kilobytes, and attaching it to
	// everything would pay that on every message to establish something the
	// recipient already knows after the first one.
	if typ == didcomm.TypeContactRequest {
		if kel := s.ownKELForIntroduction(fromAID); len(kel) > 0 {
			env.SenderKEL = kel
		}
	}
	raw, _ := json.Marshal(env)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Post(peer.Endpoint, "application/didcomm-envelope+json", bytes.NewReader(raw))
	if err != nil {
		s.recordTraffic(fromAID, jwm.ID, conversationOf(body), "didcomm.message.sent", "error",
			fmt.Sprintf("%s to %s could not be delivered: %v", typ, toAID, err), nil)
		return jwm.ID, 0, fmt.Errorf("delivery: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	status := "ok"
	if resp.StatusCode >= 300 {
		status = "error"
	}
	s.recordTraffic(fromAID, jwm.ID, conversationOf(body), "didcomm.message.sent", status,
		fmt.Sprintf("%s to %s, answered %d", typ, toAID, resp.StatusCode), nil)
	return jwm.ID, resp.StatusCode, nil
}

// recordTraffic writes one message that crossed this agent to the signed log,
// linked by the message's own id and filed under its conversation when it has
// one, so what was sent and received can be shown later rather than only what
// was done because of it. about, when given, is what the row commits to.
func (s *CoreServer) recordTraffic(caller, messageID, conversation, event, status, why string, about []byte) {
	if s.ActivityLog == nil {
		return
	}
	s.ActivityLog.RecordGovernanceEventAbout(permission.CallerContext{
		CallerAID: caller, CorrelationID: messageID, WorkItem: conversation, Transport: "didcomm", Reason: clampWhy(why),
	}, event, status, about)
}
