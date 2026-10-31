package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/internal/coretypes"
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

// sealedRequest and sealedResponse are the one format every sealed request
// uses, whichever side sends it.
type (
	sealedRequest  = didcomm.SealedRequest
	sealedResponse = didcomm.SealedResponse
)

const (
	sealedRequestType  = didcomm.TypeSealedRequest
	sealedResponseType = didcomm.TypeSealedResponse
	// sealedMaxBody bounds what one envelope may carry. An encrypted tunnel is
	// still an unauthenticated entry point until the envelope opens, so the
	// work done before that point has to be bounded.
	sealedMaxBody = didcomm.SealedMaxBody
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
		if status := statusForUnreadable(err, http.StatusForbidden); status != http.StatusForbidden {
			// Answered to anybody, so nothing about where or how this
			// Identity Agent keeps its data. The log has the detail.
			log.Printf("[sealed] an envelope arrived and could not be opened here: %v", err)
			writeSealedError(w, status, "this Identity Agent cannot open envelopes right now")
			return
		}
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

	// Freshness and replay, which this did not check at all.
	//
	// The sending side sets a two-minute expiry and says in a comment why: a
	// long window is a long window in which a captured envelope can be
	// replayed. It then went unread here, so the window was in fact forever —
	// anyone who kept a copy of a sealed request could send it again, and a
	// request that transfers something or changes something would happen again
	// with it.
	//
	// Checked in the same order and against the same limits as an ordinary
	// message, because a sealed request is not a weaker thing than a message.
	exp, terr := time.Parse(time.RFC3339, jwm.ExpiresTime)
	if terr != nil {
		writeSealedError(w, http.StatusBadRequest, "this request does not say when it expires")
		return
	}
	now := time.Now().UTC()
	if !now.Before(exp) {
		writeSealedError(w, http.StatusForbidden, "this request has expired")
		return
	}
	if exp.After(now.Add(maxEnvelopeLifetime)) {
		writeSealedError(w, http.StatusForbidden, "this request claims to be valid for too long")
		return
	}
	if seenBefore(jwm.ID, exp) {
		writeSealedError(w, http.StatusConflict, "this request has already been carried out")
		return
	}

	var inner sealedRequest
	if err := json.Unmarshal(jwm.Body, &inner); err != nil {
		writeSealedError(w, http.StatusBadRequest, "the request inside could not be read")
		return
	}

	rec, err := s.replaySealed(r, inner, senderDID.AID)
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
func (s *CoreServer) replaySealed(outer *http.Request, inner sealedRequest, senderAID string) (*httptest.ResponseRecorder, error) {
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
		case "Authorization", "Cookie", "Host", "Connection", "Content-Length", LocalOwnerSecretHeader:
			continue
		case headerSealedFrom:
			// Set below from the envelope, which is the only thing that
			// establishes who sent this. A caller-supplied copy would let them
			// name themselves.
			continue
		}
		req.Header.Set(k, v)
	}
	// A sealed request is NEVER a local request, whatever address it arrived on.
	//
	// This took the outer connection's address, which is right for rate limiting
	// and catastrophic for authorisation. An agent on rented hardware is reached
	// through a tunnel client that connects to it over loopback — so the outer
	// address is 127.0.0.1 — and ownership here is "loopback, and no forwarding
	// headers". The sender writes the inner headers, so they simply omit the
	// forwarding ones, and every registered peer's request would be served as
	// the owner. The deployment that made it exploitable is the one this
	// transport was built for.
	//
	// So the inner request is marked as what it is: something that arrived from
	// somewhere else. Rate limiting keeps a usable address in a header, which is
	// not what ownership is decided on.
	req.RemoteAddr = sealedRemoteAddr
	req.Header.Set(headerSealedFrom, senderAID)

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
	peer, known, err := s.peerFor(skid)
	if err != nil {
		return nil, nil, err
	}
	if !known {
		// A sender the owner has already accepted as a contact is finishing a
		// step the owner authorised. A stranger still gets nothing.
		if resolved, _ := s.resolveKnownContactAsPeer(skid); resolved {
			if peer, known, err = s.peerFor(skid); err != nil {
				return nil, nil, err
			}
		}
	}
	if !known {
		// A sender an add-on recognises, such as an AI agent's body sealing
		// to this Identity Agent from the keys it enrolled with. What it may
		// then do is decided by the routes the request inside reaches, which
		// check its signature again.
		if did, ok := s.sealedSenderOfAnAddon(skid); ok {
			peer, known = peerRecord{AID: skid, DID: did}, true
		}
	}
	if !known {
		return nil, nil, fmt.Errorf("this agent has no relationship with the sender of this envelope")
	}

	if len(env.Recipients) == 0 {
		return nil, nil, fmt.Errorf("this envelope names no recipient")
	}
	kid := env.Recipients[0].Header.Kid
	has, err := s.hasKeySet(kid)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: this agent could not load the keys to open it", coretypes.ErrKeysUnavailable)
	}
	if !has {
		return nil, nil, fmt.Errorf("this envelope is addressed to an identity this agent does not hold")
	}
	keys, err := s.keySetFor(kid)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: this agent could not load the keys to open it", coretypes.ErrKeysUnavailable)
	}
	return &peer.DID, keys, nil
}

// sealedTransportPath is where envelopes arrive.
const sealedTransportPath = didcomm.SealedTransportPath

// sealedRemoteAddr is the address a replayed request appears to come from.
//
// Deliberately not loopback and deliberately not routable: it exists to be
// unmistakably "not local" to anything deciding authority, while still being a
// parseable address for anything that only wants to log or count.
const sealedRemoteAddr = "192.0.2.1:0"

// headerSealedFrom names the peer whose envelope carried a request, set from
// the envelope and stripped from anything the caller sent.
const headerSealedFrom = "X-IA-Sealed-From"

func writeSealedError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "sealed_transport",
		"detail": detail,
	})
}
