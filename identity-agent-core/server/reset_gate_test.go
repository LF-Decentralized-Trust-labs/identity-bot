package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A reset request must be refused unless it comes from the local owner.
// /api/reset is irreversible — it clears identity, contacts, settings and the
// KEL — and the server binds 0.0.0.0 with the tunnel forwarding the whole port,
// so an ungated handler is reachable by anyone who learns the URL.
func TestHandleResetRejectsNonLocalOwner(t *testing.T) {
	s := &CoreServer{}

	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		wantStatus int
	}{
		{"remote address", "203.0.113.9:51000", nil, http.StatusForbidden},
		{"lan address", "192.168.0.81:51000", nil, http.StatusForbidden},
		{"loopback behind a proxy", "127.0.0.1:51000",
			map[string]string{"X-Forwarded-For": "203.0.113.9"}, http.StatusForbidden},
		{"loopback behind cloudflare", "127.0.0.1:51000",
			map[string]string{"Cf-Connecting-Ip": "203.0.113.9"}, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/reset", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			s.handleReset(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d — an ungated reset is a remote wipe",
					rec.Code, tc.wantStatus)
			}
		})
	}
}

// The gate must not break the local UI, which calls reset over loopback with no
// forwarding headers. A nil DataStore would panic if the request got through,
// so reaching any status other than 403 proves the gate let it pass.
func TestHandleResetAllowsLocalOwnerPastTheGate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected the local-owner request to pass the gate and reach ResetAll")
		}
	}()

	s := &CoreServer{} // nil DataStore: panics iff the gate allowed the request through
	req := httptest.NewRequest(http.MethodPost, "/api/reset", nil)
	req.RemoteAddr = "127.0.0.1:51000"
	s.handleReset(httptest.NewRecorder(), req)
}
