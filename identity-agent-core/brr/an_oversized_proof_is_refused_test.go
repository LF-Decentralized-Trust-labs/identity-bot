package brr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/internal/boundedread"
)

func TestAnOversizedBulkProofIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"signed_by":"` + strings.Repeat("a", int(boundedread.Document)+10) + `"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	if _, err := c.FetchBulkProof("reg", "b"); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized proof accepted: %v", err)
	}
}
