package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Fixed key material is for test vectors. Its private half can be rebuilt by
// anyone from its seed, so an identity founded on it would belong to everyone.
// A request that asks for it is refused, not quietly given real keys.
func TestAHybridInceptionFromFixedMaterialIsRefused(t *testing.T) {
	aMachineThatMayFound(t)
	s := agentWithNoIdentity(t)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/hybrid-inception", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
		rec := httptest.NewRecorder()
		s.handleHybridInception(rec, req)
		return rec
	}

	if rec := post(`{"synthetic":true}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "synthetic") {
		t.Fatalf("a hybrid inception from fixed material was answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(`{"name":"real"}`); rec.Code != http.StatusCreated {
		t.Fatalf("a hybrid inception from real keys was answered %d %s", rec.Code, rec.Body.String())
	}
}
