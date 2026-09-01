package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A router with the middleware in front of it, so what is being tested is what
// actually runs rather than the handler on its own.
func aFrontEndsRouter(t *testing.T, s *CoreServer) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Use(s.refuseWhatBelongsToTheAgent(r))
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		r.Post("/controller/sign", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		// The shape that matters: a route this core would answer correctly and
		// about nobody.
		r.Get("/identity", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"initialized":false}`))
		})
		r.Get("/credentials", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"credentials":[]}`))
		})
		r.Delete("/contacts/{aid}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	return r
}

func ask(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	h.ServeHTTP(rec, req)
	return rec
}

func pointItAt(t *testing.T, s *CoreServer) {
	t.Helper()
	if err := s.beAFrontEndFor(AFrontEndFor{
		AgentAID: "EAGENT", AgentURL: "https://box.example.test",
	}); err != nil {
		t.Fatal(err)
	}
}

// A front end refuses a question about an identity rather than answering it
// about nobody.
//
// This is the whole point, and the reason it needs a test: the wrong behaviour
// is not an error. A core with no identity answers "no credentials" and "not
// initialized" perfectly correctly, and a screen still calling this machine
// shows that as the person's own with nothing on either side reporting a
// problem.
func TestAFrontEndRefusesQuestionsAboutAnIdentity(t *testing.T) {
	s := agentWithNoIdentity(t)
	h := aFrontEndsRouter(t, s)

	// Before: it answers, which is exactly the danger.
	if rec := ask(t, h, http.MethodGet, "/api/credentials"); rec.Code != http.StatusOK {
		t.Fatalf("precondition: expected the misleading answer, got %d", rec.Code)
	}

	pointItAt(t, s)

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/identity"},
		{http.MethodGet, "/api/credentials"},
		{http.MethodDelete, "/api/contacts/EWHOEVER"},
	} {
		rec := ask(t, h, c.method, c.path)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s was answered by a computer that holds no identity: %d %s",
				c.method, c.path, rec.Code, rec.Body.String())
		}
		// The refusal has to say where the question should have gone, or
		// somebody reading it cannot act on it.
		if !strings.Contains(rec.Body.String(), "https://box.example.test") {
			t.Fatalf("the refusal does not name the agent: %s", rec.Body.String())
		}
	}
}

// What is about THIS COMPUTER keeps working, or the front end cannot do the one
// job it is still running for.
func TestAFrontEndStillAnswersAboutItself(t *testing.T) {
	s := agentWithNoIdentity(t)
	h := aFrontEndsRouter(t, s)
	pointItAt(t, s)

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/health"},
		{http.MethodPost, "/api/controller/sign"},
	} {
		if rec := ask(t, h, c.method, c.path); rec.Code != http.StatusOK {
			t.Fatalf("%s %s was refused, so this computer cannot act for an identity "+
				"at all: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

// An unreadable record refuses rather than reverting to answering.
//
// Read as "no record", a corrupt file would quietly put this core back to
// answering about identities — the exact state the record exists to leave, and
// it would happen silently.
func TestAnUnreadableRecordRefusesRatherThanForgets(t *testing.T) {
	s := agentWithNoIdentity(t)
	h := aFrontEndsRouter(t, s)
	pointItAt(t, s)

	if err := os.WriteFile(s.frontEndFile(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := ask(t, h, http.MethodGet, "/api/credentials")
	if rec.Code == http.StatusOK {
		t.Fatal("a corrupt record put this computer back to answering about an " +
			"identity it does not hold")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected a refusal saying it cannot tell, got %d %s", rec.Code, rec.Body.String())
	}
}

// Half a record is not a record — it is the state the writer refuses to create.
func TestAnAddressWithoutAnIdentityIsRefused(t *testing.T) {
	s := agentWithNoIdentity(t)
	if err := s.beAFrontEndFor(AFrontEndFor{AgentURL: "https://box.example.test"}); err == nil {
		t.Fatal("this computer was pointed at an address with no identity, so it " +
			"would trust whatever answers there")
	}
	if front, err := s.whatThisCoreIsAFrontEndFor(); err != nil || front != nil {
		t.Fatalf("a refused write left something behind: %+v (%v)", front, err)
	}
}

// An identity here is not a thing to overwrite.
func TestAComputerHoldingAnIdentityDoesNotBecomeAFrontEnd(t *testing.T) {
	s := serverWithIdentity(t, "EHELDHERE")
	if err := s.beAFrontEndFor(AFrontEndFor{
		AgentAID: "EAGENT", AgentURL: "https://box.example.test",
	}); err == nil {
		t.Fatal("a computer holding an identity was made a front end for another, " +
			"leaving the identity it holds unreachable through the software that " +
			"holds it")
	}
}

// Saying what this installation is can be undone, or a machine pointed at an
// agent it can no longer reach is finished.
func TestAFrontEndCanGoBackToHoldingItsOwnIdentity(t *testing.T) {
	s := agentWithNoIdentity(t)
	h := aFrontEndsRouter(t, s)
	pointItAt(t, s)

	if err := s.stopBeingAFrontEnd(); err != nil {
		t.Fatal(err)
	}
	if rec := ask(t, h, http.MethodGet, "/api/credentials"); rec.Code != http.StatusOK {
		t.Fatalf("it is still refusing after being told it holds its own identity: %d", rec.Code)
	}

	// And the route reports the same thing the middleware acts on.
	rec := httptest.NewRecorder()
	s.handleReadFrontEndFor(rec, httptest.NewRequest(http.MethodGet, "/api/controller/front-end-for", nil))
	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["front_end_for"] != nil {
		t.Fatalf("the route still says this computer is a front end: %+v", body)
	}
}
