package endpointclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/internal/boundedread"
)

func bigServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":{"content":[{"text":"` + strings.Repeat("a", int(boundedread.Document)+10) + `"}]}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAnOversizedInvokeAnswerIsRefused(t *testing.T) {
	srv := bigServer(t)
	if _, err := New(srv.URL, "tok").Invoke(context.Background(), "cap", nil); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized answer accepted: %v", err)
	}
}

func TestAnOversizedProvisionAnswerIsRefused(t *testing.T) {
	srv := bigServer(t)
	if _, err := ProvisionAgent(context.Background(), srv.URL, "n", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized answer accepted: %v", err)
	}
}
