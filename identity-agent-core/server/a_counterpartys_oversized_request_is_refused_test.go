package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/internal/boundedread"
)

// An inbound DIDComm message and a login callback over the limit are refused
// with 413, not read in part.
func TestAnOversizedInboundRequestIsRefused(t *testing.T) {
	body := `{"pad":"` + strings.Repeat("a", int(boundedread.Document)+10) + `"}`
	s := &CoreServer{}
	for name, h := range map[string]http.HandlerFunc{"didcomm": s.handleDIDCommInbound, "login callback": s.handleLoginCallback} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// The pairing offer a box returns is bounded.
func TestAnOversizedPairingOfferIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"public_key":"k","pad":"` + strings.Repeat("a", int(boundedread.Document)) + `"}`))
	}))
	defer srv.Close()
	if offer, err := boxPairingBegin(srv.Client(), srv.URL); err == nil || offer != nil {
		t.Fatalf("%v %v", offer, err)
	}
}

// What can be stored can be fetched back: the upload bound is the one the
// archive limit is derived from, so the two cannot drift apart.
func TestTheUploadBoundAndTheArchiveLimitAgree(t *testing.T) {
	if maxArchiveUpload != boundedread.ArchiveUploadBase64 || boundedread.Archive < maxArchiveUpload/4*3 {
		t.Fatalf("upload %d, archive %d", int64(maxArchiveUpload), boundedread.Archive)
	}
}
