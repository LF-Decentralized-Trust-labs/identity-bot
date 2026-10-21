package didcomm

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
)

// A request carried inside an envelope, so nothing between the two ends can
// read it, and its answer, carried back the same way.
//
// One format, used by every sender: an Identity Agent reaching a peer, and a
// machine that is an AI agent's body reaching its Identity Agent. The receiving
// side opens the envelope and replays the request through its ordinary router.

// SealedRequest is an ordinary request, as carried inside an envelope.
type SealedRequest struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Query  string            `json:"query,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	// BodyB64 rather than a nested object, because the body may be anything and
	// re-encoding it would change bytes a handler is entitled to see exactly.
	BodyB64 string `json:"body_b64,omitempty"`
}

// SealedResponse is what comes back, inside an envelope of its own.
type SealedResponse struct {
	Status  int               `json:"status"`
	Header  map[string]string `json:"header,omitempty"`
	BodyB64 string            `json:"body_b64,omitempty"`
}

// SealedResult is what came back, once opened.
type SealedResult struct {
	Status int
	Header map[string]string
	Body   []byte
}

// SealedTransportPath is where an Identity Agent takes sealed requests.
const SealedTransportPath = "/api/sealed"

// SealedMaxBody bounds what one envelope may carry.
const SealedMaxBody = 8 << 20

// SendSealed carries one request from sender to the identity whose keys are
// to, at base, and returns the answer once it has been opened and shown to
// come from to unaltered.
func SendSealed(ctx context.Context, client *http.Client, sender *KeySet, to *DID, base string,
	req SealedRequest, messageID string) (*SealedResult, error) {
	inner, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("could not encode the request: %w", err)
	}
	now := time.Now().UTC()
	env, err := PackAuthcrypt(sender, to, &JWM{
		ID:          messageID,
		Type:        TypeSealedRequest,
		From:        "did:keri:" + sender.AID,
		To:          []string{"did:keri:" + to.AID},
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
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+SealedTransportPath, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/didcomm-envelope+json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", to.AID, err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, SealedMaxBody))
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
	var replyEnv Envelope
	if err := json.Unmarshal(answer, &replyEnv); err != nil {
		return nil, fmt.Errorf("the answer is not an envelope: %w", err)
	}
	reply, err := UnpackAuthcrypt(sender, to, &replyEnv)
	if err != nil {
		// The answer did not come from the identity addressed, or was altered
		// on the way back. Both mean the same thing to a caller: do not use it.
		return nil, fmt.Errorf("the answer could not be opened, so it did not come "+
			"from %s unaltered: %w", to.AID, err)
	}
	if reply.Type != TypeSealedResponse {
		return nil, fmt.Errorf("the answer is not a response to a request")
	}
	var out SealedResponse
	if err := json.Unmarshal(reply.Body, &out); err != nil {
		return nil, fmt.Errorf("the response inside could not be read: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(out.BodyB64)
	if err != nil {
		return nil, fmt.Errorf("the response body is not valid base64: %w", err)
	}
	return &SealedResult{Status: out.Status, Header: out.Header, Body: decoded}, nil
}
