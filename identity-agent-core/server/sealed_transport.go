package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"identity-agent-core/didcomm"
)

// Carrying a request nobody in the middle can read.
//
// An agent is reached over TLS, and on rented hardware that TLS is terminated
// by somebody else — a proxy on the host, a content network in front of it, or
// both. Each of them decrypts, reads, and re-encrypts. The disk is now
// protected against exactly those parties, which leaves the traffic as the one
// place a customer's data is still handed over in the clear.
//
// So the payload is encrypted between the two ends that already know each
// other. Pairing establishes a relationship with keys on both sides; this
// carries an ordinary request inside that relationship. What sits between sees
// an opaque envelope, its size, and when it arrived.
//
// It is NOT a second API. The request inside is the same request that would
// have been made directly, and it is replayed through the same router — so
// every endpoint works through this without knowing it exists, and no handler
// can be reachable one way and not the other.
//
// What this does not hide, stated so nobody has to infer it: that a request
// happened, roughly how large it was, and when. Traffic analysis is not
// addressed here and cannot be addressed at this layer.

// sealedRequest is an ordinary request, as carried inside an envelope.
type sealedRequest struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Query  string            `json:"query,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	// BodyB64 rather than a nested object, because the body may be anything and
	// re-encoding it would change bytes a handler is entitled to see exactly.
	BodyB64 string `json:"body_b64,omitempty"`
}

// sealedResponse is what comes back, inside an envelope of its own.
type sealedResponse struct {
	Status  int               `json:"status"`
	Header  map[string]string `json:"header,omitempty"`
	BodyB64 string            `json:"body_b64,omitempty"`
}

const (
	sealedRequestType  = didcomm.TypeSealedRequest
	sealedResponseType = didcomm.TypeSealedResponse
	// sealedMaxBody bounds what one envelope may carry. An encrypted tunnel is
	// still an unauthenticated entry point until the envelope opens, so the
	// work done before that point has to be bounded.
	sealedMaxBody = 8 << 20
)

// handleSealedTransport opens an envelope, runs the request inside it, and
// seals the answer back.
func (s *CoreServer) handleSealedTransport(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, sealedMaxBody))
	if err != nil {
		writeSealedError(w, http.StatusBadRequest, "could not read the envelope")
		return
	}

	var env didcomm.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeSealedError(w, http.StatusBadRequest, "this is not an envelope")
		return
	}

	// Who this is from and who it is for, resolved exactly as an ordinary
	// message would be. The peer registry is the only authority on senders, and
	// nothing is minted for an anonymous caller — the same rule the inbound
	// message path states, for the same reason: a pairwise identifier appears
	// in published addresses, so anyone who read one could otherwise make this
	// agent do expensive work on demand.
	senderDID, keys, err := s.sealedParties(&env)
	if err != nil {
		writeSealedError(w, http.StatusForbidden, err.Error())
		return
	}

	jwm, err := didcomm.UnpackAuthcrypt(keys, senderDID, &env)
	if err != nil {
		// Deliberately not specific. Distinguishing "wrong key" from "corrupt"
		// from "not for us" tells somebody probing which of those they achieved.
		writeSealedError(w, http.StatusForbidden, "this envelope could not be opened")
		return
	}
	if jwm.Type != sealedRequestType {
		writeSealedError(w, http.StatusBadRequest, "this envelope does not carry a request")
		return
	}

	var inner sealedRequest
	if err := json.Unmarshal(jwm.Body, &inner); err != nil {
		writeSealedError(w, http.StatusBadRequest, "the request inside could not be read")
		return
	}

	rec, err := s.replaySealed(r, inner)
	if err != nil {
		writeSealedError(w, http.StatusBadRequest, err.Error())
		return
	}

	out := sealedResponse{
		Status:  rec.Code,
		Header:  map[string]string{},
		BodyB64: base64.StdEncoding.EncodeToString(rec.Body.Bytes()),
	}
	// Only what a caller needs to interpret the body. Copying every header back
	// would carry whatever the stack added on the way out, which is not part of
	// the answer and may describe this machine.
	if ct := rec.Header().Get("Content-Type"); ct != "" {
		out.Header["Content-Type"] = ct
	}

	answer, err := json.Marshal(out)
	if err != nil {
		writeSealedError(w, http.StatusInternalServerError, "could not encode the answer")
		return
	}
	reply, err := didcomm.PackAuthcrypt(keys, senderDID, &didcomm.JWM{
		ID:          jwm.ID,
		Type:        sealedResponseType,
		From:        jwm.To[0],
		To:          []string{jwm.From},
		CreatedTime: time.Now().UTC().Format(time.RFC3339),
		Body:        answer,
	})
	if err != nil {
		writeSealedError(w, http.StatusInternalServerError, "could not seal the answer")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reply)
}

// replaySealed runs the carried request through this agent's own router.
//
// Through the router rather than a switch of its own, so that an endpoint
// cannot be reachable through one door and not the other — which is how a
// forgotten authorisation check becomes a way in.
func (s *CoreServer) replaySealed(outer *http.Request, inner sealedRequest) (*httptest.ResponseRecorder, error) {
	if inner.Path == "" || inner.Path[0] != '/' {
		return nil, fmt.Errorf("the request inside names no path")
	}
	// The tunnel must not carry itself. A request for this endpoint, inside
	// this endpoint, is either a mistake or an attempt to make the agent
	// recurse until it runs out of stack.
	if inner.Path == sealedTransportPath {
		return nil, fmt.Errorf("a sealed request cannot carry another")
	}

	raw, err := base64.StdEncoding.DecodeString(inner.BodyB64)
	if err != nil {
		return nil, fmt.Errorf("the body inside is not valid base64")
	}

	target := inner.Path
	if inner.Query != "" {
		target += "?" + inner.Query
	}
	req := httptest.NewRequest(inner.Method, target, bytes.NewReader(raw))
	for k, v := range inner.Header {
		// Hop-by-hop and identity-bearing headers are dropped rather than
		// forwarded: the envelope already established who the caller is, and
		// letting them also assert it in a header would give two answers to one
		// question.
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "Cookie", "Host", "Connection", "Content-Length":
			continue
		}
		req.Header.Set(k, v)
	}
	// The caller's real address, for anything that rate limits. Taken from the
	// outer connection, because the inside is written by the caller.
	req.RemoteAddr = outer.RemoteAddr

	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec, nil
}

// sealedParties resolves who an envelope is from and which of this agent's
// keysets it is addressed to.
//
// Both come from the envelope's own headers and are then checked against what
// this agent already holds. A sender that is not a registered peer is refused
// without anything being created for them, and a recipient identifier this
// agent does not already have a keyset for is refused rather than minted —
// minting on a stranger's say-so is work an unauthenticated caller gets to
// demand.
func (s *CoreServer) sealedParties(env *didcomm.Envelope) (*didcomm.DID, *didcomm.KeySet, error) {
	skid := env.Protected.Skid
	if skid == "" {
		return nil, nil, fmt.Errorf("this envelope does not say who it is from")
	}
	didcommMu.Lock()
	peer, known := s.loadPeers()[skid]
	didcommMu.Unlock()
	if !known {
		// A sender the owner has already accepted as a contact is finishing a
		// step the owner authorised. A stranger still gets nothing.
		if resolved, _ := s.resolveKnownContactAsPeer(skid); resolved {
			didcommMu.Lock()
			peer, known = s.loadPeers()[skid]
			didcommMu.Unlock()
		}
	}
	if !known {
		return nil, nil, fmt.Errorf("this agent has no relationship with the sender of this envelope")
	}

	if len(env.Recipients) == 0 {
		return nil, nil, fmt.Errorf("this envelope names no recipient")
	}
	kid := env.Recipients[0].Header.Kid
	if !s.hasKeySet(kid) {
		return nil, nil, fmt.Errorf("this envelope is addressed to an identity this agent does not hold")
	}
	keys, err := s.keySetFor(kid)
	if err != nil {
		return nil, nil, fmt.Errorf("this agent could not load the keys to open it")
	}
	return &peer.DID, keys, nil
}

// sealedTransportPath is where envelopes arrive.
const sealedTransportPath = "/api/sealed"

func writeSealedError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "sealed_transport",
		"detail": detail,
	})
}
