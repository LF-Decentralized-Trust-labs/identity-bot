package recovery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnOversizedBackupArchiveIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()
	old := maxBackupArchiveBytes
	maxBackupArchiveBytes = 50
	defer func() { maxBackupArchiveBytes = old }()
	if b, err := FetchBackupOnlyArchive(srv.URL, "E1", "a.bin"); err == nil || b != nil {
		t.Fatalf("an oversized archive was returned: %d bytes, %v", len(b), err)
	}
}
