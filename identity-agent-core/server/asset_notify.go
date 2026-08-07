package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/didcomm"
	"identity-agent-core/login"
)

// A device this agent owns asking it to tell somebody something.
//
// The device cannot deliver the message itself, and should not. Sending
// requires a post-quantum envelope, a keyset, and a standing relationship with
// the recipient — all of which this agent already has and the device would have
// to acquire separately.
//
// The stronger reason is whose name is on the message. A device is a component;
// the relationship the recipient has is with the identity that owns it. A
// message from an identifier somebody has never seen is one they are right to
// distrust, and a message from the identity they already know is one they can
// evaluate. So the device says what needs saying, and its owner says it.

// Headers a machine signs with. Deliberately parallel to the owner's, and
// deliberately distinct: an asset is not the owner, and a signature that could
// be presented as either would make the weaker key do the stronger key's work.
const (
	headerAssetSig       = "X-IA-Asset-Sig"
	headerAssetTimestamp = "X-IA-Asset-Timestamp"
	headerAssetAID       = "X-IA-Asset-AID"
)

// verifyAssetSignature returns the asset that signed this request.
//
// The canonical string is the same one the owner signs — method, path,
// timestamp and a digest of the body — so a signature cannot be moved to
// another endpoint, replayed later, or reused with a different body. Reusing it
// rather than inventing a second format means there is one construction to get
// right and one to review.
func (s *CoreServer) verifyAssetSignature(r *http.Request) (*asset.Asset, error) {
	if s.assetHandler == nil || s.assetHandler.Store == nil {
		return nil, fmt.Errorf("this agent has no assets")
	}
	sig := r.Header.Get(headerAssetSig)
	claimedAID := r.Header.Get(headerAssetAID)
	stamp := r.Header.Get(headerAssetTimestamp)
	if sig == "" || claimedAID == "" || stamp == "" {
		return nil, fmt.Errorf("a machine's request must carry %s, %s and %s",
			headerAssetAID, headerAssetTimestamp, headerAssetSig)
	}

	signedAt, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return nil, fmt.Errorf("%s must be RFC3339", headerAssetTimestamp)
	}
	now := time.Now().UTC()
	if diff := now.Sub(signedAt); diff > signedRequestWindow || diff < -signedRequestWindow {
		return nil, fmt.Errorf("signed request is outside the %s window", signedRequestWindow)
	}

	// Find the asset by the identifier it claims, then check the signature
	// against the key recorded when it enrolled. The claim is only a lookup —
	// nothing is trusted until the signature matches.
	var found *asset.Asset
	for _, a := range s.assetHandler.Store.ListAssets() {
		if a.PairwiseAID == claimedAID {
			candidate := a
			found = &candidate
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no machine of this agent's is %s", claimedAID)
	}
	if found.PublicKey == "" {
		// An asset the agent minted itself, whose key lives in the owner's
		// derivation tree rather than on a machine. It has nothing to sign with
		// and nothing here should pretend otherwise.
		return nil, fmt.Errorf("%s did not enrol with a key of its own", claimedAID)
	}

	pub, err := login.DecodeVerkey(found.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("the key recorded for this machine is unusable: %w", err)
	}

	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	ok, err := login.VerifyString(
		canonicalRequestString(r.Method, r.URL.Path, stamp, body), sig, pub)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("signature does not match the key %s enrolled with", claimedAID)
	}

	// Spent last, so a bad signature cannot burn a good one by arriving first.
	if rememberSignature(sig, now) {
		return nil, fmt.Errorf("this signed request has already been used")
	}
	return found, nil
}

// handleAssetNotify delivers a message on an enrolled machine's behalf.
func (s *CoreServer) handleAssetNotify(w http.ResponseWriter, r *http.Request) {
	sender, err := s.verifyAssetSignature(r)
	if err != nil {
		writeError(w, http.StatusForbidden, "Not one of this agent's machines", err.Error())
		return
	}

	var req struct {
		// ToAID is who to tell. An identifier, not an address: this agent
		// resolves how to reach them, and a machine naming a URL directly could
		// point a message anywhere.
		ToAID string `json:"to_aid"`
		// ToAgentURL is where that identifier can be reached, for the case this
		// agent has no standing relationship with them. That is the ordinary
		// case whenever the first message in a relationship travels outward.
		ToAgentURL string `json:"to_agent_url"`
		Kind       string `json:"kind"`
		Severity   string `json:"severity"`
		Title      string `json:"title"`
		Body       string `json:"body"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}
	if strings.TrimSpace(req.ToAID) == "" || strings.TrimSpace(req.Title) == "" {
		writeError(w, http.StatusBadRequest, "Nothing to send",
			"to_aid and title are both required")
		return
	}

	// The machine's own identifier goes on the message, taken from the verified
	// signature rather than from the body. What it says is its own; who it is
	// is not up to it.
	payload := map[string]string{
		"kind":     req.Kind,
		"severity": req.Severity,
		"title":    req.Title,
		"body":     req.Body,
	}
	if req.ExpiresAt != "" {
		payload["expires_at"] = req.ExpiresAt
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not build the message", err.Error())
		return
	}

	// Sent from this agent's own identity, so it arrives from the party the
	// recipient has a relationship with rather than from one of its components.
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		writeError(w, http.StatusConflict, "No identity",
			"this agent has no identity, so it cannot send anything")
		return
	}

	if req.ToAgentURL != "" {
		// Recorded before sending, because delivery needs a peer and somebody
		// who has never messaged us is not one yet.
		if err := s.rememberPeerAt(req.ToAID, req.ToAgentURL); err != nil {
			writeError(w, http.StatusBadGateway,
				"Could not reach the recipient's agent", err.Error())
			return
		}
	}

	// The status code is returned SEPARATELY from the error, and both have to be
	// checked. A recipient that refuses the envelope — because it does not know
	// us, because the signature failed, because it is a replay — answers 4xx and
	// produces no error at all, so a caller that reads only err reports every
	// rejection as a successful delivery.
	//
	// That is the worst available outcome here. The device stops retrying, the
	// operator sees a clean log, and the person who needed the message never
	// hears. A warning that silently fails is indistinguishable from one that
	// was never needed.
	_, status, err := s.SendDIDCommMessage(identity.AID, req.ToAID, didcomm.TypeNotification, raw)
	if err != nil {
		// The device is told plainly, because it is the only party that knows
		// this needed saying and it has to decide whether to try again.
		writeError(w, http.StatusBadGateway, "The message was not delivered", err.Error())
		return
	}
	if status < 200 || status > 299 {
		writeError(w, http.StatusBadGateway, "The recipient refused the message",
			fmt.Sprintf("their agent answered %d — it may not know this identity yet", status))
		return
	}

	writeJSONResponse(w, map[string]string{
		"status":   "sent",
		"from_aid": identity.AID,
		"to_aid":   req.ToAID,
		"on_behalf_of": fmt.Sprintf("%s (%s)",
			sender.DisplayName, sender.PairwiseAID),
	})
}

// rememberPeerAt fetches an agent's public DIDComm keys and records it as a
// peer, so a message can be encrypted to it.
//
// Needed because the recipient may have no prior relationship with us, and
// without one there is nothing to encrypt to. Peers are otherwise registered by
// an owner by hand, which cannot be the answer when a device needs to reach
// somebody unattended.
//
// Only PUBLIC key material crosses this call, and it comes from the agent that
// owns the identifier rather than from the machine that asked us to send. A
// machine naming both a recipient and the keys to encrypt to them could have
// the message encrypted to itself.
func (s *CoreServer) rememberPeerAt(aid, agentURL string) error {
	base := strings.TrimRight(agentURL, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return fmt.Errorf("an agent address must be an http(s) URL")
	}

	didcommMu.Lock()
	_, already := s.loadPeers()[aid]
	didcommMu.Unlock()
	if already {
		return nil
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(base + "/api/didcomm/did?aid=" + aid)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s did not publish keys for %s (%d)", base, aid, resp.StatusCode)
	}

	var did didcomm.DID
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&did); err != nil {
		return fmt.Errorf("could not read the keys %s published: %w", base, err)
	}
	// The identifier the keys are for must be the one we asked about. Without
	// this an agent could answer any question with its own keys and receive
	// messages meant for somebody else.
	if did.AID != aid {
		return fmt.Errorf("%s answered with keys for %s, not %s", base, did.AID, aid)
	}

	didcommMu.Lock()
	defer didcommMu.Unlock()
	peers := s.loadPeers()
	peers[aid] = peerRecord{
		AID: aid, DID: did,
		Endpoint: canonicalPeerEndpoint(base),
		AddedAt:  time.Now().UTC(),
	}
	return s.savePeers(peers)
}
