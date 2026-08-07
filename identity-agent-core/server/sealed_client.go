package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/didcomm"
)

// Making a request that nothing in the middle can read.
//
// The other half of the sealed transport. An agent already accepts requests
// carried inside an envelope; this sends them, so the protection stops being a
// mechanism nothing uses and starts being the way an agent is reached.
//
// It lives here, in the core, rather than in either app. Both a desktop and a
// phone run this same core — one beside the interface, one embedded in it — so
// putting it here means one implementation, tested once, rather than the same
// envelope format written twice and drifting. It also keeps the keys where they
// already are.
//
// What this hides: the request, the response, and which endpoint was called.
// What it does not: that a request happened, roughly its size, and when.

// agentBaseFromInbox recovers an agent's base address from the endpoint stored
// in a peer record.
//
// What is stored is the peer's DIDComm inbox — the address plus "/didcomm" —
// because messaging is what the record was created for. The sealed transport
// lives at a different path on the same agent, so appending to the inbox
// address rather than to the base produced ".../didcomm/api/sealed", which no
// agent serves.
//
// That was not caught by the round-trip test, because the test built its peer
// record by hand with a bare address, and so exercised a shape the code that
// creates peer records never produces. The test now builds the endpoint the way
// rememberPeerAt does.
func agentBaseFromInbox(endpoint string) string {
	return strings.TrimSuffix(strings.TrimRight(endpoint, "/"), "/didcomm")
}

// SealedResult is what came back, once opened.
type SealedResult struct {
	Status int
	Header map[string]string
	Body   []byte
}

// SealedRequest carries one request to a remote agent and brings the answer
// back, with everything in between opaque to whatever is in between.
//
// toAID is the remote agent's pairwise identifier and must already be a peer:
// the relationship carries the keys, and without it there is nothing to encrypt
// to. That is the same requirement ordinary messaging has, for the same reason.
func (s *CoreServer) SealedRequest(ctx context.Context, fromAID, toAID, method, path string, body []byte, header map[string]string) (*SealedResult, error) {
	sender, err := s.keySetFor(fromAID)
	if err != nil {
		return nil, fmt.Errorf("no keys to send as %s: %w", fromAID, err)
	}
	didcommMu.Lock()
	peer, known := s.loadPeers()[toAID]
	didcommMu.Unlock()
	if !known {
		return nil, fmt.Errorf("no relationship with %s, so there is nothing to encrypt a request to", toAID)
	}
	if peer.Endpoint == "" {
		return nil, fmt.Errorf("%s has no address to send to", toAID)
	}

	inner, err := json.Marshal(sealedRequest{
		Method:  method,
		Path:    path,
		Header:  header,
		BodyB64: base64.StdEncoding.EncodeToString(body),
	})
	if err != nil {
		return nil, fmt.Errorf("could not encode the request: %w", err)
	}

	now := time.Now().UTC()
	env, err := didcomm.PackAuthcrypt(sender, &peer.DID, &didcomm.JWM{
		ID:          newMessageID(),
		Type:        sealedRequestType,
		From:        "did:keri:" + fromAID,
		To:          []string{"did:keri:" + toAID},
		CreatedTime: now.Format(time.RFC3339),
		// Short, because a request is answered immediately or not at all. A
		// long window is a long window in which a captured envelope can be
		// replayed.
		ExpiresTime: now.Add(2 * time.Minute).Format(time.RFC3339),
		Body:        inner,
	})
	if err != nil {
		return nil, fmt.Errorf("could not seal the request: %w", err)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		agentBaseFromInbox(peer.Endpoint)+sealedTransportPath, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/didcomm-envelope+json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", toAID, err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, sealedMaxBody))
	if err != nil {
		return nil, fmt.Errorf("could not read the answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The transport refused before anything was opened. Reported as itself
		// rather than as the inner request's status, because a caller that
		// confused "the agent said 403" with "the transport said 403" would
		// retry the wrong thing.
		return nil, fmt.Errorf("the sealed transport was refused with %d: %s",
			resp.StatusCode, bytes.TrimSpace(answer))
	}

	var replyEnv didcomm.Envelope
	if err := json.Unmarshal(answer, &replyEnv); err != nil {
		return nil, fmt.Errorf("the answer is not an envelope: %w", err)
	}
	reply, err := didcomm.UnpackAuthcrypt(sender, &peer.DID, &replyEnv)
	if err != nil {
		// The answer did not come from the agent addressed, or was altered on
		// the way back. Both mean the same thing to a caller: do not use it.
		return nil, fmt.Errorf("the answer could not be opened, so it did not come "+
			"from %s unaltered: %w", toAID, err)
	}
	if reply.Type != sealedResponseType {
		return nil, fmt.Errorf("the answer is not a response to a request")
	}

	var out sealedResponse
	if err := json.Unmarshal(reply.Body, &out); err != nil {
		return nil, fmt.Errorf("the response inside could not be read: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(out.BodyB64)
	if err != nil {
		return nil, fmt.Errorf("the response body is not valid base64: %w", err)
	}
	return &SealedResult{Status: out.Status, Header: out.Header, Body: decoded}, nil
}
