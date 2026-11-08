package watcher

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/internal/boundedread"
)

func serveOversized(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"a":"` + strings.Repeat("a", int(boundedread.Document)) + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A peer's answer over the limit is refused by both watcher clients.
func TestAWatcherAnswerOverTheLimitIsRefused(t *testing.T) {
	srv := serveOversized(t)
	if _, _, err := (&L2Client{HTTPClient: srv.Client()}).QueryDigest(context.Background(), srv.URL, "E1", 0); !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("L2: %v", err)
	}
	l3 := &L3Client{HTTPClient: srv.Client(), AllowLocal: func(string) bool { return true }}
	if _, err := l3.CrossCheck(context.Background(), srv.URL, KelCheckRequest{}); !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("L3: %v", err)
	}
}
