package agenthost

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
)

// Call sends one request to the Identity Agent, signed by this machine's key
// and sealed to the Identity Agent's keys, so nothing between the two — a
// relay, a proxy, a content network ending TLS — reads the request or its
// answer.
func (h *Host) Call(method, path string, body []byte) (int, []byte, error) {
	return h.CallContext(context.Background(), method, path, body)
}

// CallContext is Call, bounded by ctx.
func (h *Host) CallContext(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	st, err := h.loadState()
	if err != nil {
		return 0, nil, fmt.Errorf("this machine has not enrolled: %w", err)
	}
	iaKeys, err := h.identityAgentKeys(&st)
	if err != nil {
		return 0, nil, err
	}
	signer, _ := h.signer()
	host, _, err := agentbody.Identity(signer)
	if err != nil {
		return 0, nil, err
	}
	ks, err := h.keySet(host)
	if err != nil {
		return 0, nil, err
	}
	u, err := url.Parse(path)
	if err != nil {
		return 0, nil, err
	}
	headers, err := h.signedHeaders(method, u.RequestURI(), body)
	if err != nil {
		return 0, nil, err
	}
	id := make([]byte, 18)
	if _, err := rand.Read(id); err != nil {
		return 0, nil, err
	}
	res, err := didcomm.SendSealed(ctx, h.sealedClient(), ks, iaKeys, st.IdentityAgentURL, didcomm.SealedRequest{
		Method: method, Path: u.Path, Query: u.RawQuery, Header: headers,
		BodyB64: base64.StdEncoding.EncodeToString(body),
	}, "ahm-"+base64.RawURLEncoding.EncodeToString(id))
	if err != nil {
		return 0, nil, err
	}
	return res.Status, res.Body, nil
}

// sealedClient allows for a long-poll: the Identity Agent holds an inbox
// request open for up to 25 seconds.
func (h *Host) sealedClient() *http.Client {
	if h.HTTP != nil {
		return h.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// identityAgentKeys are the keys requests are sealed to. A machine enrolled
// before they were kept fetches them now, and accepts them only as the
// enrolment did: committed to, or signed by, the key the Identity Agent's own
// verified log ends with.
func (h *Host) identityAgentKeys(st *State) (*didcomm.DID, error) {
	if st.IdentityAgentKeys != nil && st.IdentityAgentKeys.AID == st.IdentityAgent {
		return st.IdentityAgentKeys, nil
	}
	kel, current, err := h.verifiedLog(st.IdentityAgentURL, st.IdentityAgent, nil)
	if err != nil {
		return nil, err
	}
	did, err := h.sealingKeysOf(st.IdentityAgentURL, st.IdentityAgent, kel, current)
	if err != nil {
		return nil, err
	}
	st.IdentityAgentKeys = did
	if err := h.saveState(*st); err != nil {
		return nil, err
	}
	return did, nil
}

// Move points this body at a new address for the same Identity Agent — after
// the Identity Agent's public address changed. The new address is believed
// only if it answers as the same identity, with a key log that verifies and
// sealing keys belonging to it, so moving cannot hand this body to someone
// else.
func (h *Host) Move(url string) (State, error) {
	st, err := h.loadState()
	if err != nil {
		return State{}, fmt.Errorf("this machine has not enrolled: %w", err)
	}
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	var holds func(sn int, said string) bool
	if st.KeyStateSAID != "" {
		holds = func(sn int, said string) bool { return sn == st.KeyStateSN && said == st.KeyStateSAID }
	}
	kel, current, err := h.verifiedLog(url, st.IdentityAgent, holds)
	if err != nil {
		return State{}, fmt.Errorf("%s is not the Identity Agent this machine enrolled with: %w", url, err)
	}
	did, err := h.sealingKeysOf(url, st.IdentityAgent, kel, current)
	if err != nil {
		return State{}, err
	}
	st.IdentityAgentURL, st.IdentityAgentKeys = url, did
	if err := h.saveState(st); err != nil {
		return State{}, err
	}
	return st, nil
}
