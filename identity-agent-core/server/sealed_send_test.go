package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// End to end through the door an app actually uses: the app hands its request
// to the core on its own device, that core seals it, and the answer comes back
// — with a recording proxy in the middle seeing neither.
func TestAnAppsRequestReachesAHostedAgentWithoutTheMiddleReadingIt(t *testing.T) {
	caller, callerAID, responder, responderAID := twoAgents(t)

	r := chi.NewRouter()
	r.Post("/api/profile", func(w http.ResponseWriter, req *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(req.Body).Decode(&in)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"stored": in["legal_name"]})
	})
	responder.router = r

	var seen [][]byte
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		seen = append(seen, body)
		rec := httptest.NewRecorder()
		responder.handleSealedTransport(rec, requestWithBody(req, body))
		out := rec.Body.Bytes()
		seen = append(seen, out)
		w.WriteHeader(rec.Code)
		_, _ = w.Write(out)
	}))
	defer front.Close()

	didcommMu.Lock()
	peers := caller.loadPeers()
	p := peers[responderAID]
	p.Endpoint = front.URL + "/didcomm"
	peers[responderAID] = p
	_ = caller.savePeers(peers)
	didcommMu.Unlock()

	const secret = "Alexandra Whitfield-Barnes"
	send, _ := json.Marshal(sealedSendRequest{
		ToAID:   responderAID,
		FromAID: callerAID,
		Method:  http.MethodPost,
		Path:    "/api/profile",
		BodyB64: base64.StdEncoding.EncodeToString([]byte(`{"legal_name":"` + secret + `"}`)),
	})

	rec := httptest.NewRecorder()
	caller.handleSealedSend(rec, ownerRequest("POST", sealedSendPath, strings.NewReader(string(send)), caller))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out sealedSendResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(out.BodyB64)
	if !strings.Contains(string(body), secret) {
		t.Errorf("the answer did not come back: %s", body)
	}

	// THE POINT.
	if len(seen) < 2 {
		t.Fatal("nothing passed through the middle, so this proves nothing")
	}
	for i, b := range seen {
		if strings.Contains(string(b), secret) {
			t.Fatalf("the operator saw the name in observation %d", i)
		}
		if strings.Contains(string(b), "/api/profile") {
			t.Fatalf("the operator saw which endpoint was used in observation %d", i)
		}
	}
}

// It sends as this device's identity, so anyone who could call it could speak
// as the owner to the owner's own agent.
func TestSendingIsOwnerOnly(t *testing.T) {
	caller, _, _, responderAID := twoAgents(t)
	send, _ := json.Marshal(sealedSendRequest{ToAID: responderAID, Path: "/api/health"})

	rec := httptest.NewRecorder()
	caller.handleSealedSend(rec, httptest.NewRequest("POST", sealedSendPath, strings.NewReader(string(send))))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a non-owner was allowed to send as this device: status %d", rec.Code)
	}
}

// A failure to send privately must be reported, never retried in the clear —
// a fallback that quietly works is one an attacker can force by breaking this
// path, which is the whole protection undone by being helpful.
func TestAFailureToSendPrivatelyIsNotRetriedInTheClear(t *testing.T) {
	caller, callerAID, _, _ := twoAgents(t)
	send, _ := json.Marshal(sealedSendRequest{
		ToAID: "ESTRANGER", FromAID: callerAID, Path: "/api/health",
	})

	rec := httptest.NewRecorder()
	caller.handleSealedSend(rec, ownerRequest("POST", sealedSendPath, strings.NewReader(string(send)), caller))
	if rec.Code == http.StatusOK {
		t.Fatal("a request to somebody with no relationship reported success")
	}
	if !strings.Contains(rec.Body.String(), "privately") {
		t.Errorf("the failure does not say the request was not sent: %s", rec.Body.String())
	}
}

// Carrying itself would either loop or wrap one envelope in another and look
// like it worked.
func TestTheDoorCannotCarryItself(t *testing.T) {
	caller, callerAID, _, responderAID := twoAgents(t)
	for _, path := range []string{sealedSendPath, sealedTransportPath} {
		send, _ := json.Marshal(sealedSendRequest{ToAID: responderAID, FromAID: callerAID, Path: path})
		rec := httptest.NewRecorder()
		caller.handleSealedSend(rec, ownerRequest("POST", sealedSendPath, strings.NewReader(string(send)), caller))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s was accepted as a target: status %d", path, rec.Code)
		}
	}
}

// A sealed request is never a local request, whatever address it arrived on.
//
// This is the shape of the escalation: an agent on rented hardware is reached
// through a tunnel client that connects over loopback, so the OUTER address is
// 127.0.0.1. Ownership is "loopback and no forwarding headers", and the sender
// writes the inner headers — so they simply omit the forwarding ones and every
// registered peer's request would be served as the owner. The deployment that
// made it exploitable is the one this transport exists for.
func TestASealedRequestIsNeverTreatedAsLocal(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	var sawOwner bool
	mux := chi.NewRouter()
	mux.Get("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		sawOwner = isLocalOwnerRequest(r)
		w.WriteHeader(http.StatusOK)
	})
	s.router = mux

	// The outer connection arrives on loopback, exactly as it does behind a tunnel.
	outer := httptest.NewRequest(http.MethodPost, sealedTransportPath, nil)
	outer.RemoteAddr = "127.0.0.1:41000"

	if _, err := s.replaySealed(outer, sealedRequest{
		Method: "GET", Path: "/api/probe",
		// No forwarding headers, because the sender chooses not to send any.
	}, "EPEER"); err != nil {
		t.Fatal(err)
	}
	if sawOwner {
		t.Fatal("a peer's sealed request was served as the owner")
	}
}

// And the sender must not be able to name themselves.
func TestAPeerCannotAssertWhoSentTheRequest(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	var saw string
	mux := chi.NewRouter()
	mux.Get("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		saw = r.Header.Get(headerSealedFrom)
		w.WriteHeader(http.StatusOK)
	})
	s.router = mux

	if _, err := s.replaySealed(httptest.NewRequest(http.MethodPost, "/", nil), sealedRequest{
		Method: "GET", Path: "/api/probe",
		Header: map[string]string{headerSealedFrom: "ESOMEBODY-IMPORTANT"},
	}, "EREAL-SENDER"); err != nil {
		t.Fatal(err)
	}
	if saw != "EREAL-SENDER" {
		t.Errorf("the request claims to be from %q — the sender named themselves", saw)
	}
}
