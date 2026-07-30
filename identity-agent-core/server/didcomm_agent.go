package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"identity-agent-core/didcomm"
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
