package recovery

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/internal/boundedread"
)

func serveAnOversizedAnswer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"band":"high","score":1,"share_b64":"AAAA","public_key_b64":"AAAA","pad":"` +
			strings.Repeat("a", int(boundedread.Document)) + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A holder, a provider or a machine that answers with more than the limit is
// refused, and the first part of what it sent is not used.
func TestAnOversizedAnswerFromAHolderOrProviderIsRefused(t *testing.T) {
	srv := serveAnOversizedAnswer(t)
	if _, _, err := (&StubAuthProviderGate{BaseURL: srv.URL, HTTPClient: srv.Client()}).CurrentBand(); !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("assurance provider: %v", err)
	}
	if got, err := askAMachineToHold(srv.Client(), srv.URL, "E1", nil, AgreeToHold{}); err == nil || got != nil {
		t.Fatalf("machine to hold: %v %v", got, err)
	}
	share, _, err := askOneHolder(srv.Client(), backup.ShareHolder{ID: "h", Address: srv.URL}, "E1", backup.SealedShare{})
	if err == nil || share != nil {
		t.Fatalf("holder's share: %v %v", share, err)
	}
}

// The download client has a timeout, and it is the one a stalled peer meets.
func TestAStalledBackupDownloadTimesOut(t *testing.T) {
	if backupDownloadClient.Timeout <= 0 {
		t.Fatal("the backup download client has no timeout: a peer that stops sending holds it for ever")
	}
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	old := backupDownloadClient
	backupDownloadClient = &http.Client{Timeout: 150 * time.Millisecond}
	defer func() { backupDownloadClient = old }()
	start := time.Now()
	if b, err := FetchBackupOnlyArchive(srv.URL, "E1", "a.bin"); err == nil || b != nil {
		t.Fatalf("a download that never finished returned: %d bytes, %v", len(b), err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the timeout did not end the download: %v", time.Since(start))
	}
}
