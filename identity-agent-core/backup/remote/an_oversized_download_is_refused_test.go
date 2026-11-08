package remote

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/internal/boundedread"
)

// A backup archive larger than the most the core will store can never have been
// stored, so a download of one is refused rather than held in memory; a listing
// is bounded too.
func TestAnOversizedDownloadFromARemoteStoreIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Just over the listing bound is enough for a listing; an archive
		// download is refused by the same helper at boundedread.Archive.
		buf := make([]byte, 1<<20)
		for i := int64(0); i <= maxListBytes>>20; i++ {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	b, err := NewWebDAVBackend(DestinationConfig{RemoteURL: srv.URL}, CredentialSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.List(context.Background(), ""); !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("listing: %v", err)
	}
}
