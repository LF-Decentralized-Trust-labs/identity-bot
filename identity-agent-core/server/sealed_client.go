package server

import (
	"context"
	"encoding/base64"
	"fmt"
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

// A peer record stores one address, and two different paths are derived from
// it: the DIDComm inbox for messages, and the sealed transport for requests.
//
// What is stored is the inbox — the agent's address with "/didcomm" on the end
// — because messaging is what the record was created for. So the sealed path
// has to be taken from the base, and appending to the inbox instead produced
// ".../didcomm/api/sealed", which no agent serves.
//
// The two helpers below are the only places that decide this, and
// canonicalPeerEndpoint is applied on the way in, so the shape is established
// once at the boundary rather than assumed at each use. Three writers set this
// field and two of them appended "/didcomm" by hand; the third stored whatever
// an owner posted. An invariant depended on in two directions and enforced in
// neither is one that holds until somebody registers a peer the ordinary way.

// canonicalPeerEndpoint puts an address into the one shape the readers expect,
// accepting either an agent base or an inbox that already has the suffix.
func canonicalPeerEndpoint(addr string) string {
	base := strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(addr), "/"), "/didcomm")
	if base == "" {
		return ""
	}
	return base + "/didcomm"
}

// agentBaseFromInbox recovers the agent's own address, which is what paths
// other than the inbox hang off.
func agentBaseFromInbox(endpoint string) string {
	return strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(endpoint), "/"), "/didcomm")
}

// SealedResult is what came back, once opened.
type SealedResult = didcomm.SealedResult

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
	peer, known, err := s.peerFor(toAID)
	if err != nil {
		return nil, err
	}
	if !known {
		return nil, fmt.Errorf("no relationship with %s, so there is nothing to encrypt a request to", toAID)
	}
	if peer.Endpoint == "" {
		return nil, fmt.Errorf("%s has no address to send to", toAID)
	}
	return didcomm.SendSealed(ctx, &http.Client{Timeout: 30 * time.Second}, sender, &peer.DID,
		agentBaseFromInbox(peer.Endpoint), sealedRequest{
			Method:  method,
			Path:    path,
			Header:  header,
			BodyB64: base64.StdEncoding.EncodeToString(body),
		}, newMessageID())
}
