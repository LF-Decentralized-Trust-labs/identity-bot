package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/schemas"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

func TestTheAIAgentGrantSchemaIsServedByItsIdentifier(t *testing.T) {
	s := newAuthTestServer(t)
	said := schemas.AIAgentGrant.Schema.SAID
	if got := classify("GET", "/public/schemas/{said}"); got != accessPublic {
		t.Fatalf("the schema route is %q; a verifier could not resolve the schema", got)
	}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("said", said)
	r := httptest.NewRequest("GET", "/public/schemas/"+said, nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	s.handlePublicSchemaServe(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("served %d", rec.Code)
	}
	got, err := keri.VerifySchema(rec.Body.Bytes())
	if err != nil || got != said {
		t.Fatalf("the served document digests to %q (%v), not %s", got, err, said)
	}
}
