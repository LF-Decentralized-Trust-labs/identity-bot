package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/sandbox"
)

// registerSigner mints an ed25519 keypair, registers its public key under aid so
// publicDidWebsPubKey resolves it, and returns the private key for signing.
func registerSigner(t *testing.T, aid string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pairwiseKeys.Lock()
	pairwiseKeys.m[aid] = base64.RawURLEncoding.EncodeToString(pub)
	pairwiseKeys.Unlock()
	return priv
}

// signedEnvelopeRequest builds an MCP request carrying a valid signed envelope.
func signedEnvelopeRequest(t *testing.T, priv ed25519.PrivateKey, aid, method string, params []byte, nonce, ts string) *[3]string {
	t.Helper()
	payload := canonicalRequestPayload(method, params, nonce, ts)
	sig := ed25519.Sign(priv, []byte(payload))
	sigQB64, err := iacrypto.MatterFixedQB64("0B", sig)
	if err != nil {
		t.Fatal(err)
	}
	_ = aid
	return &[3]string{sigQB64, nonce, ts}
}

func TestEnvelopeAbsentIsNoOp(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	r := httptest.NewRequest("POST", "/api/mcp", nil)
	caller := sandbox.CallerContext{CallerAID: "EAgent", AuthLevel: "bearer"}
	if err := s.verifyRequestEnvelope(r, "tools/call", []byte("{}"), &caller); err != nil {
		t.Fatalf("absent envelope must be a no-op, got %v", err)
	}
	if caller.EnvelopeVerified {
		t.Fatal("no envelope → EnvelopeVerified must stay false")
	}
	if caller.AuthLevel != "bearer" {
		t.Fatalf("auth level should stay bearer, got %q", caller.AuthLevel)
	}
}

func TestEnvelopeValidVerifies(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	priv := registerSigner(t, "EAgentValid")
	params := []byte(`{"capability_id":"infra.zone.list"}`)
	nonce := "nonce-valid-1"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	env := signedEnvelopeRequest(t, priv, "EAgentValid", "tools/call", params, nonce, ts)

	r := httptest.NewRequest("POST", "/api/mcp", nil)
	r.Header.Set(envSigHeader, env[0])
	r.Header.Set(envNonceHeader, env[1])
	r.Header.Set(envTSHeader, env[2])
	caller := sandbox.CallerContext{CallerAID: "EAgentValid", AuthLevel: "bearer"}
	if err := s.verifyRequestEnvelope(r, "tools/call", params, &caller); err != nil {
		t.Fatalf("valid envelope should verify, got %v", err)
	}
	if !caller.EnvelopeVerified || caller.AuthLevel != "signed_request" {
		t.Fatalf("valid envelope should set EnvelopeVerified + signed_request, got %v / %q", caller.EnvelopeVerified, caller.AuthLevel)
	}
}

func TestEnvelopeStaleRejected(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	priv := registerSigner(t, "EAgentStale")
	params := []byte("{}")
	nonce := "nonce-stale"
	ts := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10) // outside 5m window
	env := signedEnvelopeRequest(t, priv, "EAgentStale", "tools/call", params, nonce, ts)
	r := httptest.NewRequest("POST", "/api/mcp", nil)
	r.Header.Set(envSigHeader, env[0])
	r.Header.Set(envNonceHeader, env[1])
	r.Header.Set(envTSHeader, env[2])
	caller := sandbox.CallerContext{CallerAID: "EAgentStale"}
	if err := s.verifyRequestEnvelope(r, "tools/call", params, &caller); err == nil {
		t.Fatal("a stale timestamp must be rejected")
	}
}

func TestEnvelopeReplayRejected(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	priv := registerSigner(t, "EAgentReplay")
	params := []byte("{}")
	nonce := "nonce-replay-once"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	env := signedEnvelopeRequest(t, priv, "EAgentReplay", "tools/call", params, nonce, ts)
	build := func() (*sandbox.CallerContext, error) {
		r := httptest.NewRequest("POST", "/api/mcp", nil)
		r.Header.Set(envSigHeader, env[0])
		r.Header.Set(envNonceHeader, env[1])
		r.Header.Set(envTSHeader, env[2])
		caller := sandbox.CallerContext{CallerAID: "EAgentReplay"}
		return &caller, s.verifyRequestEnvelope(r, "tools/call", params, &caller)
	}
	if _, err := build(); err != nil {
		t.Fatalf("first use of the nonce should verify, got %v", err)
	}
	if _, err := build(); err == nil {
		t.Fatal("replaying the same nonce must be rejected")
	}
}

func TestEnvelopeTamperedRejected(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	priv := registerSigner(t, "EAgentTamper")
	params := []byte(`{"capability_id":"infra.zone.list"}`)
	nonce := "nonce-tamper"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	env := signedEnvelopeRequest(t, priv, "EAgentTamper", "tools/call", params, nonce, ts)
	r := httptest.NewRequest("POST", "/api/mcp", nil)
	r.Header.Set(envSigHeader, env[0])
	r.Header.Set(envNonceHeader, env[1])
	r.Header.Set(envTSHeader, env[2])
	caller := sandbox.CallerContext{CallerAID: "EAgentTamper"}
	// Verify against DIFFERENT params than were signed → signature must fail.
	if err := s.verifyRequestEnvelope(r, "tools/call", []byte(`{"capability_id":"infra.dns_record.delete"}`), &caller); err == nil {
		t.Fatal("a signature over different params must be rejected")
	}
}

func TestEnvelopeSignerMismatchRejected(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	priv := registerSigner(t, "EAgentReal")
	params := []byte("{}")
	nonce := "nonce-mismatch"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	env := signedEnvelopeRequest(t, priv, "EAgentReal", "tools/call", params, nonce, ts)
	r := httptest.NewRequest("POST", "/api/mcp", nil)
	r.Header.Set(envSigHeader, env[0])
	r.Header.Set(envNonceHeader, env[1])
	r.Header.Set(envTSHeader, env[2])
	// Caller authenticated as a DIFFERENT AID than the signer → reject.
	caller := sandbox.CallerContext{CallerAID: "EAgentOther"}
	if err := s.verifyRequestEnvelope(r, "tools/call", params, &caller); err == nil {
		t.Fatal("signer AID not matching the authenticated caller must be rejected")
	}
}
