package endpointclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/login"
)

// The client's signed envelope must verify with the SAME function the endpoint
// uses (login.VerifyDetachedSig) over the SAME canonical payload — i.e. real
// interop with the Phase-4 server verifier, not a parallel reimplementation.
func TestSignedEnvelopeInteropWithServerVerifier(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := NewLocalKeySigner(seed, "EAgentSDK")
	if err != nil {
		t.Fatal(err)
	}

	var gotBody []byte
	var gotHeader http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHeader = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"status\":200,\"audit_event_id\":7}"}]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "iamcp_token", WithSigner(signer))
	res, err := c.Invoke(context.Background(), "infra.zone.list", nil)
	if err != nil {
		t.Fatalf("invoke failed: %v", err)
	}
	if res.Status != 200 || res.AuditEventID != 7 {
		t.Fatalf("unexpected result: %+v", res)
	}

	// Bearer token present.
	if got := gotHeader.Get("Authorization"); got != "Bearer iamcp_token" {
		t.Fatalf("bearer token header = %q", got)
	}
	// Signer AID header present.
	if got := gotHeader.Get("X-IA-Signer-AID"); got != "EAgentSDK" {
		t.Fatalf("signer AID header = %q", got)
	}

	// Rebuild the canonical payload from the exact bytes the server received and
	// verify the signature with the server's verifier + the signer's public key.
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatal(err)
	}
	payload := CanonicalPayload(req.Method, req.Params, gotHeader.Get("X-IA-Nonce"), gotHeader.Get("X-IA-Timestamp"))
	pub, err := base64.RawURLEncoding.DecodeString(signer.PublicKeyB64())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := login.VerifyDetachedSig(payload, gotHeader.Get("X-IA-Signature"), pub)
	if err != nil || !ok {
		t.Fatalf("client envelope must verify with the server verifier: ok=%v err=%v", ok, err)
	}
}

// Without a Signer the client sends a plain bearer request — no envelope headers.
func TestNoSignerSendsPlainBearer(t *testing.T) {
	var gotHeader http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"status\":200}"}]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "iamcp_plain")
	if _, err := c.Invoke(context.Background(), "infra.zone.list", map[string]interface{}{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	if gotHeader.Get("X-IA-Signature") != "" {
		t.Fatal("no signer → there must be no envelope signature header")
	}
	if gotHeader.Get("Authorization") != "Bearer iamcp_plain" {
		t.Fatal("bearer token should still be sent")
	}
}
