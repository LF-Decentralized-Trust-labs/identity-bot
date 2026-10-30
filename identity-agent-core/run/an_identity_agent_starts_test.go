package run

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"identity-agent-core/server"

	"github.com/go-chi/chi/v5"
)

const ownerSecret = "the-owner-secret-for-this-test-0123456789"

// freePort is a port nothing listens on now.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// An app's start-up runs in order: what must precede the configuration, the
// configuration as the app adjusts it, the server made with it, what the app
// adds to the server, the server serving that, and what the app ends once
// the server has stopped.
func TestAnAppsStartUpRunsInOrder(t *testing.T) {
	dir, port := t.TempDir(), freePort(t)
	t.Setenv("AGENT_DATA_DIR", dir)
	// Set here so what BeforeConfig sets is put back when the test ends.
	t.Setenv("PORT", "")
	t.Setenv(server.LocalOwnerSecretEnv, "")
	var happened []string
	served := 0
	err := start(Options{
		Name: "an-app",
		BeforeConfig: func() error {
			happened = append(happened, "before config")
			os.Setenv(server.LocalOwnerSecretEnv, ownerSecret)
			return os.Setenv("PORT", fmt.Sprint(port))
		},
		Config: func(cfg *server.Config) {
			happened = append(happened, "config")
			if cfg.Port != port || cfg.DataDir != dir {
				t.Errorf("the configuration was not read after BeforeConfig: port %d, data %s", cfg.Port, cfg.DataDir)
			}
		},
		Prepare: func(s *server.CoreServer, cfg server.Config) (func(), error) {
			happened = append(happened, "prepare")
			s.MountExtraRoutes(func(r chi.Router) {
				r.Get("/an-apps-own", func(w http.ResponseWriter, r *http.Request) { served++ })
			})
			return func() { happened = append(happened, "stopped") }, nil
		},
	}, nil, func() {
		happened = append(happened, "serving")
		// While serving, the app's own route is there.
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/an-apps-own", port), nil)
		req.Header.Set(server.LocalOwnerSecretHeader, ownerSecret)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(happened, ", "); got != "before config, config, prepare, serving, stopped" {
		t.Fatalf("the start-up ran as: %s", got)
	}
	if served != 1 {
		t.Fatalf("the route the app added was served %d times while the server ran, want once", served)
	}
}

// What keeps an app from starting is said, and the server is not started.
func TestAnAppThatCannotPrepareDoesNotStart(t *testing.T) {
	t.Setenv("AGENT_DATA_DIR", t.TempDir())
	t.Setenv("PORT", fmt.Sprint(freePort(t)))
	waited := false
	err := start(Options{
		BeforeConfig: func() error { return errors.New("no executor") },
	}, nil, func() { waited = true })
	if err == nil || err.Error() != "no executor" || waited {
		t.Fatalf("an app that failed before its configuration started anyway: %v (served: %v)", err, waited)
	}
	err = start(Options{
		Prepare: func(*server.CoreServer, server.Config) (func(), error) { return nil, errors.New("no roster") },
	}, nil, func() { waited = true })
	if err == nil || err.Error() != "no roster" || waited {
		t.Fatalf("an app that failed to prepare started anyway: %v (served: %v)", err, waited)
	}
}

// What an app's Prepare set up is ended even when Prepare also fails.
func TestAFailedPrepareStillEndsWhatItStarted(t *testing.T) {
	t.Setenv("AGENT_DATA_DIR", t.TempDir())
	t.Setenv("PORT", fmt.Sprint(freePort(t)))
	ended, waited := false, false
	err := start(Options{
		Prepare: func(*server.CoreServer, server.Config) (func(), error) {
			return func() { ended = true }, errors.New("half done")
		},
	}, nil, func() { waited = true })
	if err == nil || err.Error() != "half done" || waited {
		t.Fatalf("a failed Prepare started the server: %v (served: %v)", err, waited)
	}
	if !ended {
		t.Fatal("what a failed Prepare had started was never ended")
	}
}
