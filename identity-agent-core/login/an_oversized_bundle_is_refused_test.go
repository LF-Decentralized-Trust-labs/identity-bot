package login

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/internal/boundedread"
)

func TestAnOversizedChallengeBundleIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("a", int(boundedread.Document)+10) + `"}`))
	}))
	defer srv.Close()
	h := &Handler{HTTPClient: srv.Client(), dataDir: t.TempDir()}
	if _, err := h.fetchChallengeBundle(srv.URL, "tok"); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized bundle accepted: %v", err)
	}
}
