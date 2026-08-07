package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// The door an owner's own app uses to reach their hosted agent privately.
//
// The encrypted transport was built, tested, and used by nothing. Every request
// an app made to a hosted agent still crossed the network readable by whatever
// terminates TLS in front of it — which on rented hardware is the machine's
// operator. A mechanism with no callers protects nobody.
//
// The reason nothing called it is worth stating, because it looks like a
// missing feature and is not: the envelope needs keys, and a browser or a
// phone app has nowhere to keep them. But it does not need to. Every desktop
// and every phone already runs this same core locally — beside the interface on
// one, embedded in it on the other — even when the interface is pointed at a
// remote agent. So the app hands its request to the core on its own device, and
// the core seals it and sends it. One implementation, where the keys already
// are, and no second one to drift.
//
// What this hides from the operator: the request, the response, and which
// endpoint was asked for. What it does not: that a request happened, roughly
// how big it was, and when.

type sealedSendRequest struct {
	// ToAID is the agent to reach. It must already be a peer — the
	// relationship is what carries the keys, and adoption is where it is
	// established.
	ToAID string `json:"to_aid"`
	// FromAID is which of this device's identities is asking. Defaults to this
	// agent's own identity.
	FromAID string `json:"from_aid,omitempty"`

	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Header  map[string]string `json:"header,omitempty"`
	BodyB64 string            `json:"body_b64,omitempty"`
}

type sealedSendResponse struct {
	Status  int               `json:"status"`
	Header  map[string]string `json:"header,omitempty"`
	BodyB64 string            `json:"body_b64,omitempty"`
}

// handleSealedSend forwards one request to a peer inside an envelope and
// returns what came back.
//
// Owner-only, and that is the whole of its access control: it sends as this
// device's identity, so anyone who could call it could speak as the owner to
// the owner's own agent. It is not a general proxy either — the target has to
// be an identity this device already has a relationship with, so it cannot be
// pointed at an arbitrary address by whoever reaches it.
func (s *CoreServer) handleSealedSend(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "sending as this device is owner only", http.StatusForbidden)
		return
	}

	var req sealedSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "could not read the request", http.StatusBadRequest)
		return
	}
	if req.ToAID == "" {
		jsonError(w, "to_aid is required: an envelope is addressed to somebody", http.StatusBadRequest)
		return
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	if req.Path == "" || req.Path[0] != '/' {
		jsonError(w, "path must be an absolute path on the agent being reached", http.StatusBadRequest)
		return
	}
	// Sending this endpoint through itself would either loop or, worse, wrap
	// one envelope in another and look like it worked.
	if req.Path == sealedSendPath || req.Path == sealedTransportPath {
		jsonError(w, "this endpoint cannot carry itself", http.StatusBadRequest)
		return
	}

	var body []byte
	if req.BodyB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.BodyB64)
		if err != nil {
			jsonError(w, "body_b64 is not valid base64", http.StatusBadRequest)
			return
		}
		body = decoded
	}

	from := req.FromAID
	if from == "" {
		id, err := s.DataStore.GetIdentity()
		if err != nil || id == nil || id.AID == "" {
			jsonError(w, "this device has no identity to send as", http.StatusConflict)
			return
		}
		from = id.AID
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	result, err := s.SealedRequest(ctx, from, req.ToAID, req.Method, req.Path, body, req.Header)
	if err != nil {
		// A failure here means the request did not arrive privately. Reported
		// as a failure rather than retried in the clear, because a fallback
		// that quietly works is one an attacker can force by breaking this
		// path — which is the whole of the protection, undone by being helpful.
		jsonError(w, fmt.Sprintf("this request was not sent, because it could not be sent "+
			"privately: %v", err), http.StatusBadGateway)
		return
	}

	jsonResponse(w, sealedSendResponse{
		Status:  result.Status,
		Header:  result.Header,
		BodyB64: base64.StdEncoding.EncodeToString(result.Body),
	})
}

const sealedSendPath = "/api/sealed/send"
