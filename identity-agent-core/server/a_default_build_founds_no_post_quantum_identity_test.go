//go:build !kerigo_pqtest

package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
)

// A build that cannot read a post-quantum key (ADR-061) founds nothing on one:
// the hybrid-inception endpoint refuses, with no identity stored, and the
// sealed machine's identity is refused before any key is made.
func TestADefaultBuildFoundsNoPostQuantumIdentity(t *testing.T) {
	aMachineThatMayFound(t)
	s := agentWithNoIdentity(t)
	for _, body := range []string{`{"name":"real"}`, `{"synthetic":true}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/hybrid-inception", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
		rec := httptest.NewRecorder()
		s.handleHybridInception(rec, req)
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "post-quantum") {
			t.Fatalf("%s was answered %d %s", body, rec.Code, rec.Body.String())
		}
	}
	if id, _ := s.DataStore.GetIdentity(); id != nil {
		t.Fatal("a refused hybrid inception stored an identity")
	}

	if box, err := newBoxIdentity("EOWNER"); !errors.Is(err, iacrypto.ErrNoPostQuantumCodes) || box != nil {
		t.Fatalf("a sealed machine's identity: %v, %v", box, err)
	}
}
