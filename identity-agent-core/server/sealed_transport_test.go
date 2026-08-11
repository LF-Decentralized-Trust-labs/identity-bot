package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The tunnel carries requests. It must not exempt them, and it must not become
// a way in for anyone the agent has no relationship with.

func postEnvelope(t *testing.T, s *CoreServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, sealedTransportPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleSealedTransport(rec, req)
	return rec
}

// A stranger gets nothing, and nothing is created on their behalf. A pairwise
// identifier appears in published addresses, so anyone who read one could
// otherwise make this agent mint keys and write files on demand.
func TestAnEnvelopeFromAStrangerIsRefused(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	env := `{"mode":"authcrypt","protected":{"skid":"EUNKNOWNSENDER"},"recipients":[{"header":{"kid":"EUS"}}],"ciphertext":"x","iv":"y"}`
	rec := postEnvelope(t, s, env)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 for a sender with no relationship", rec.Code)
	}
}

// An envelope with no sender is refused rather than treated as anonymous.
func TestAnEnvelopeThatNamesNoSenderIsRefused(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	rec := postEnvelope(t, s, `{"mode":"authcrypt","protected":{},"ciphertext":"x"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 when the envelope names no sender", rec.Code)
	}
}

func TestSomethingThatIsNotAnEnvelopeIsRefused(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	for _, body := range []string{"", "not json", "[]", "null"} {
		rec := postEnvelope(t, s, body)
		if rec.Code == http.StatusOK {
			t.Fatalf("%q was accepted as an envelope", body)
		}
	}
}

// The failure for an envelope that cannot be opened must not say WHY. "Wrong
// key", "corrupt", and "not addressed to us" are three different facts, and
// telling a prober which one they achieved is telling them how to proceed.
func TestOpeningFailuresDoNotSayWhichFailure(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	rec := postEnvelope(t, s, `{"mode":"authcrypt","protected":{"skid":"EA"},"recipients":[{"header":{"kid":"EB"}}],"ciphertext":"x"}`)
	body := rec.Body.String()
	for _, leak := range []string{"signature", "key_agreement", "body_hash", "decrypt"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("the refusal names the failure mode (%q): %s", leak, body)
		}
	}
}

// A request that carries another would let one envelope make the agent recurse.
func TestASealedRequestCannotCarryAnother(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	_, err := s.replaySealed(
		httptest.NewRequest(http.MethodPost, "/", nil),
		sealedRequest{Method: "POST", Path: sealedTransportPath},
		"EPEER",
	)
	if err == nil {
		t.Fatal("a sealed request was allowed to carry another")
	}
}

func TestARequestWithNoPathIsRefused(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	for _, path := range []string{"", "api/health", "http://elsewhere/x"} {
		if _, err := s.replaySealed(httptest.NewRequest(http.MethodPost, "/", nil),
			sealedRequest{Method: "GET", Path: path}, "EPEER"); err == nil {
			t.Errorf("path %q was accepted", path)
		}
	}
}

// The carried request goes through the ordinary router, so an endpoint cannot
// be reachable one way and not the other — which is how a forgotten
// authorisation check becomes a way in.
func TestTheCarriedRequestMeetsTheOrdinaryRouter(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	reached := false
	mux := chi.NewRouter()
	mux.Get("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"seen":true}`))
	})
	s.router = mux

	rec, err := s.replaySealed(httptest.NewRequest(http.MethodPost, "/", nil),
		sealedRequest{Method: "GET", Path: "/api/probe"}, "EPEER")
	if err != nil {
		t.Fatal(err)
	}
	if !reached {
		t.Fatal("the carried request never reached the router")
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("the router's status was not carried back: %d", rec.Code)
	}
}

// Credentials asserted inside the envelope are dropped. The envelope already
// established who the caller is; letting them also claim it in a header would
// give two answers to one question, and the weaker one is attacker-chosen.
func TestCredentialsInsideTheEnvelopeAreDropped(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	var got http.Header
	mux := chi.NewRouter()
	mux.Get("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	})
	s.router = mux

	if _, err := s.replaySealed(httptest.NewRequest(http.MethodPost, "/", nil), sealedRequest{
		Method: "GET",
		Path:   "/api/probe",
		Header: map[string]string{
			"Authorization": "Bearer somebody-elses",
			"Cookie":        "session=theirs",
			"X-Ordinary":    "kept",
		},
	}, "EPEER"); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "" {
		t.Error("an Authorization header inside the envelope reached the router")
	}
	if got.Get("Cookie") != "" {
		t.Error("a Cookie inside the envelope reached the router")
	}
	if got.Get("X-Ordinary") != "kept" {
		t.Error("an ordinary header was dropped")
	}
}

// The body is carried byte for byte. Re-encoding it would change bytes a
// handler is entitled to see exactly — a signature over a body being the case
// that matters.
func TestTheBodyIsCarriedByteForByte(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	want := []byte("{\"a\":1,  \"b\":\t2}\n")
	var got []byte
	mux := chi.NewRouter()
	mux.Post("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		got = buf.Bytes()
	})
	s.router = mux

	if _, err := s.replaySealed(httptest.NewRequest(http.MethodPost, "/", nil), sealedRequest{
		Method:  "POST",
		Path:    "/api/probe",
		BodyB64: base64.StdEncoding.EncodeToString(want),
	}, "EPEER"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the body changed in transit:\n got: %q\nwant: %q", got, want)
	}
}

// The endpoint is open in the same sense the message endpoint is: what arrives
// is an envelope. It must not be owner-gated, or the tunnel could not be used
// before the caller had already authenticated some other way.
func TestTheTunnelIsReachableAsAnEnvelope(t *testing.T) {
	if classify(http.MethodPost, sealedTransportPath) != accessPublic {
		t.Fatal("the sealed transport is not reachable, so nothing could use it")
	}
}

func TestTheResponseCarriesTheContentType(t *testing.T) {
	var out sealedResponse
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.Code = 201
	out = sealedResponse{Status: rec.Code, Header: map[string]string{"Content-Type": rec.Header().Get("Content-Type")}}
	body, _ := json.Marshal(out)
	if !strings.Contains(string(body), "application/json") {
		t.Fatal("a caller could not tell how to read the answer")
	}
}
