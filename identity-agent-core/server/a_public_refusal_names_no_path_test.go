package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/didcomm"
)

// breakRecord puts a directory where a record file belongs. Reading it fails
// on every platform with an error that names the full path, which is what a
// reply to a stranger must never repeat.
func breakRecord(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func namesNoPath(t *testing.T, where string, s *CoreServer, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%s answered %d %s, want 503", where, w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, leak := range []string{s.DataDir, filepath.Base(s.DataDir), "didcomm_keys.json", "didcomm_peers.json"} {
		if strings.Contains(body, leak) {
			t.Fatalf("%s told a stranger %q: %s", where, leak, body)
		}
	}
}

func envelopeFrom(skid string) []byte {
	raw, _ := json.Marshal(didcomm.Envelope{Protected: didcomm.ProtectedHeader{Skid: skid}})
	return raw
}

// Every reply a stranger can get while a record is unreadable says only that
// this Identity Agent cannot do it right now. Where its data lives, and so
// the account it runs under, stays in the log.
func TestAPublicRefusalNamesNoPath(t *testing.T) {
	t.Run("the public DID, keys unreadable", func(t *testing.T) {
		s := &CoreServer{DataDir: t.TempDir()}
		breakRecord(t, s.didcommKeysPath())
		w := httptest.NewRecorder()
		s.handleGetDIDCommDID(w, httptest.NewRequest(http.MethodGet, "/api/didcomm/did?aid=Eany", nil))
		namesNoPath(t, "GET /api/didcomm/did", s, w)
	})

	t.Run("inbound DIDComm, peers unreadable", func(t *testing.T) {
		s := &CoreServer{DataDir: t.TempDir()}
		breakRecord(t, s.didcommPeersPath())
		w := httptest.NewRecorder()
		s.handleDIDCommInbound(w, httptest.NewRequest(http.MethodPost, "/didcomm", bytes.NewReader(envelopeFrom("Esender"))))
		namesNoPath(t, "POST /didcomm", s, w)
	})

	t.Run("inbound DIDComm, keys unreadable", func(t *testing.T) {
		s := &CoreServer{DataDir: t.TempDir()}
		sender, _ := didcomm.GenerateKeySet("Esender")
		did, _ := sender.DID()
		if err := s.rememberPeerFromAdoption(did, "https://sender.example"); err != nil {
			t.Fatal(err)
		}
		breakRecord(t, s.didcommKeysPath())
		env := []byte(`{"protected":{"skid":"Esender"},"recipients":[{"header":{"kid":"Eus"}}]}`)
		w := httptest.NewRecorder()
		s.handleDIDCommInbound(w, httptest.NewRequest(http.MethodPost, "/didcomm", bytes.NewReader(env)))
		namesNoPath(t, "POST /didcomm", s, w)
	})

	t.Run("first contact, keys unreadable", func(t *testing.T) {
		const strangerAID, ourAID = "EStrangerWithProof", "EReceiver"
		s := witnessWithSeed(t, 1)
		s.KeriDriver = acceptingKELDriver(t)
		ours, err := s.keySetFor(ourAID)
		if err != nil {
			t.Fatal(err)
		}
		ourDID, _ := ours.DID()
		stranger, _ := didcomm.GenerateKeySet(strangerAID)
		env, err := didcomm.PackAuthcrypt(stranger, ourDID, &didcomm.JWM{
			ID: "msg-first", Type: didcomm.TypeContactRequest,
			From: "did:keri:" + strangerAID, To: []string{"did:keri:" + ourAID}, Body: []byte(`{}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		env.SenderKEL = inceptionCommittingTo(t, strangerAID, stranger)
		raw, _ := json.Marshal(env)
		breakRecord(t, s.didcommKeysPath())
		w := httptest.NewRecorder()
		s.handleDIDCommInbound(w, httptest.NewRequest(http.MethodPost, "/didcomm", bytes.NewReader(raw)))
		namesNoPath(t, "first contact", s, w)
	})

	t.Run("sealed transport, peers unreadable", func(t *testing.T) {
		s := &CoreServer{DataDir: t.TempDir()}
		breakRecord(t, s.didcommPeersPath())
		w := httptest.NewRecorder()
		s.handleSealedTransport(w, httptest.NewRequest(http.MethodPost, sealedTransportPath, bytes.NewReader(envelopeFrom("Esender"))))
		namesNoPath(t, "POST "+sealedTransportPath, s, w)
	})
}
