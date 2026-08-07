package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A request going out sealed and coming back, between two agents that know each
// other — with a recording proxy in between standing in for everything that
// terminates TLS on the way.
//
// The parts are tested elsewhere. What this establishes is that the two halves
// agree: that what one packs the other opens, that the answer travels back the
// same way, and that anything sitting in the middle sees nothing usable. Those
// are properties of the pair, and testing either alone cannot show them.

// twoAgents returns a caller and a responder that have each other registered,
// which is what pairing establishes.
func twoAgents(t *testing.T) (caller *CoreServer, callerAID string, responder *CoreServer, responderAID string) {
	t.Helper()
	caller = &CoreServer{DataDir: t.TempDir()}
	responder = &CoreServer{DataDir: t.TempDir()}
	callerAID, responderAID = "ECALLER", "ERESPONDER"

	for _, pair := range []struct {
		side       *CoreServer
		self, peer string
		other      *CoreServer
	}{
		{caller, callerAID, responderAID, responder},
		{responder, responderAID, callerAID, caller},
	} {
		ks, err := pair.side.keySetFor(pair.self)
		if err != nil {
			t.Fatal(err)
		}
		_ = ks
		otherKS, err := pair.other.keySetFor(pair.peer)
		if err != nil {
			t.Fatal(err)
		}
		did, err := otherKS.DID()
		if err != nil {
			t.Fatal(err)
		}
		didcommMu.Lock()
		peers := pair.side.loadPeers()
		peers[pair.peer] = peerRecord{DID: *did}
		_ = pair.side.savePeers(peers)
		didcommMu.Unlock()
	}
	return caller, callerAID, responder, responderAID
}

func TestARequestGoesOutSealedAndComesBack(t *testing.T) {
	caller, callerAID, responder, responderAID := twoAgents(t)

	// What the responder actually serves, reached through its ordinary router.
	r := chi.NewRouter()
	r.Post("/api/echo", func(w http.ResponseWriter, req *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(req.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"saw": in["secret"]})
	})
	responder.router = r

	// Everything the request passes through on the way, recorded.
	var seen [][]byte
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		seen = append(seen, body)
		rec := httptest.NewRecorder()
		responder.handleSealedTransport(rec, requestWithBody(req, body))
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		out := rec.Body.Bytes()
		seen = append(seen, out)
		_, _ = w.Write(out)
	}))
	defer front.Close()

	// The caller knows where the responder lives.
	didcommMu.Lock()
	peers := caller.loadPeers()
	p := peers[responderAID]
	p.Endpoint = front.URL
	peers[responderAID] = p
	_ = caller.savePeers(peers)
	didcommMu.Unlock()

	const secret = "this must never appear in the middle"
	res, err := caller.SealedRequest(context.Background(), callerAID, responderAID,
		http.MethodPost, "/api/echo", []byte(`{"secret":"`+secret+`"}`), nil)
	if err != nil {
		t.Fatalf("the round trip failed: %v", err)
	}

	if res.Status != http.StatusCreated {
		t.Errorf("status %d, want 201 — the responder's own status must survive", res.Status)
	}
	if !strings.Contains(string(res.Body), secret) {
		t.Errorf("the answer did not carry what the responder sent: %s", res.Body)
	}

	// THE POINT. Everything that passed through the middle, checked for the
	// thing it must never have been able to read.
	if len(seen) < 2 {
		t.Fatal("nothing was observed in the middle, so this proves nothing")
	}
	for i, b := range seen {
		if strings.Contains(string(b), secret) {
			t.Fatalf("the middle saw the secret in observation %d:\n%s", i, b)
		}
		if strings.Contains(string(b), "/api/echo") {
			t.Fatalf("the middle saw which endpoint was called in observation %d", i)
		}
	}
}

// An answer that did not come from the agent addressed must be refused, not
// returned. Otherwise anything in the middle could substitute a reply.
func TestAnAnswerFromSomebodyElseIsRefused(t *testing.T) {
	caller, callerAID, _, responderAID := twoAgents(t)

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A well-formed envelope this caller cannot open.
		_, _ = w.Write([]byte(`{"mode":"authcrypt","protected":{"skid":"EOTHER"},"recipients":[{"header":{"kid":"ECALLER"}}],"ciphertext":"AAAA","iv":"AAAA"}`))
	}))
	defer front.Close()

	didcommMu.Lock()
	peers := caller.loadPeers()
	p := peers[responderAID]
	p.Endpoint = front.URL
	peers[responderAID] = p
	_ = caller.savePeers(peers)
	didcommMu.Unlock()

	if _, err := caller.SealedRequest(context.Background(), callerAID, responderAID,
		http.MethodGet, "/api/health", nil, nil); err == nil {
		t.Fatal("an answer that could not be opened was returned to the caller")
	}
}

// Without a relationship there is nothing to encrypt to, and that must be said
// rather than the request going out unprotected.
func TestSendingToAStrangerIsRefusedRatherThanSentInClear(t *testing.T) {
	caller, callerAID, _, _ := twoAgents(t)
	_, err := caller.SealedRequest(context.Background(), callerAID, "ENOBODY",
		http.MethodGet, "/api/health", nil, nil)
	if err == nil {
		t.Fatal("a request to a stranger was attempted")
	}
	if !strings.Contains(err.Error(), "no relationship") {
		t.Errorf("the reason is unclear: %v", err)
	}
}

func requestWithBody(r *http.Request, body []byte) *http.Request {
	out := httptest.NewRequest(r.Method, r.URL.String(), strings.NewReader(string(body)))
	out.Header = r.Header.Clone()
	return out
}
