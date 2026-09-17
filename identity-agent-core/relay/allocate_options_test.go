package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureSigner records the exact canonical bytes it was asked to sign, so a
// test can prove the signature covers the request body — new fields included.
type captureSigner struct{ signed []byte }

func (s *captureSigner) SignCanonical(_ string, body map[string]interface{}) (string, error) {
	cb, err := CanonicalBody(body)
	if err != nil {
		return "", err
	}
	s.signed = cb
	return fmt.Sprintf("sig-%d", len(cb)), nil
}

// allocateEcho serves an allocate response, records the request body it saw, and
// echoes back the lifetime/scope/naming plus a concrete valid_until.
func allocateEcho(t *testing.T, received *map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Errorf("server: bad request body: %v", err)
		}
		*received = m
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"public_url":       "https://x.example",
			"public_hostname":  "x.example",
			"allocation_token": "tok",
			"tunnel_endpoint":  "wss://x.example/tunnel",
			"valid_until":      "2026-09-15T00:00:00Z",
			"lifetime":         "ephemeral",
			"scope":            "per-transaction",
			"naming":           "opaque",
		})
	}))
}

// The default Allocate call must not carry any of the new fields, and must leave
// the legacy fields exactly as they were — an operator that ignores the new
// protocol still sees precisely today's request.
func TestAllocateDefaultRequestUnchanged(t *testing.T) {
	var received map[string]interface{}
	srv := allocateEcho(t, &received)
	defer srv.Close()

	c := NewClient(srv.URL, "token", &captureSigner{})
	if _, err := c.Allocate(context.Background(), "EEnroll", "ERAID"); err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{"lifetime", "ttl", "scope", "naming"} {
		if _, ok := received[k]; ok {
			t.Fatalf("default request must not carry %q, got %v", k, received)
		}
	}
	if received["intent"] != "serve-didwebs-artifacts" || received["ttl_hint"] != "persistent" {
		t.Fatalf("legacy request fields changed: %v", received)
	}
	if received["raid"] != "ERAID" || received["signed_by"] != "EEnroll" {
		t.Fatalf("legacy request identity fields changed: %v", received)
	}
}

// When set, the options serialize onto the wire, and the signature covers the
// exact body that was sent (new fields included).
func TestAllocateWithOptionsWireAndSignature(t *testing.T) {
	var received map[string]interface{}
	srv := allocateEcho(t, &received)
	defer srv.Close()

	signer := &captureSigner{}
	c := NewClient(srv.URL, "token", signer)
	opts := AllocateOptions{
		Lifetime:   LifetimeEphemeral,
		TTLSeconds: 120,
		Scope:      ScopePerTransaction,
		Naming:     NamingOpaque,
	}
	resp, err := c.AllocateWithOptions(context.Background(), "EEnroll", "ERAID", opts)
	if err != nil {
		t.Fatal(err)
	}

	// New request fields present on the wire.
	if received["lifetime"] != "ephemeral" || received["scope"] != "per-transaction" || received["naming"] != "opaque" {
		t.Fatalf("request missing new fields: %v", received)
	}
	if ttl, ok := received["ttl"].(float64); !ok || ttl != 120 {
		t.Fatalf("request ttl = %v, want 120", received["ttl"])
	}
	if received["signature"] == "" || received["signature"] == nil {
		t.Fatal("request carried no signature")
	}

	// The signer signed the exact body that was sent (minus the signature it
	// then produced). Recomputing the canonical form of what the server received
	// must match the bytes the signer saw — proving the new fields are covered.
	wantSigned, err := CanonicalBody(received)
	if err != nil {
		t.Fatal(err)
	}
	if string(wantSigned) != string(signer.signed) {
		t.Fatalf("signature does not cover the sent body:\n signed: %s\n   sent: %s", signer.signed, wantSigned)
	}
	for _, sub := range []string{`"lifetime":"ephemeral"`, `"ttl":120`, `"scope":"per-transaction"`, `"naming":"opaque"`} {
		if !strings.Contains(string(signer.signed), sub) {
			t.Fatalf("signed bytes missing %s: %s", sub, signer.signed)
		}
	}

	// The echoed response semantics decode into the extended response struct.
	if resp.ValidUntil != "2026-09-15T00:00:00Z" || resp.Lifetime != "ephemeral" ||
		resp.Scope != "per-transaction" || resp.Naming != "opaque" {
		t.Fatalf("response did not decode extended fields: %+v", resp)
	}
	// Existing fields still decode.
	if resp.PublicURL != "https://x.example" || resp.AllocationToken != "tok" || resp.TunnelEndpoint != "wss://x.example/tunnel" {
		t.Fatalf("response lost existing fields: %+v", resp)
	}
}

func TestApplyAllocateOptionsOmitsWhenUnset(t *testing.T) {
	body := map[string]interface{}{"v": JSONVersion, "raid": "ERAID"}
	applyAllocateOptions(body, AllocateOptions{})
	for _, k := range []string{"lifetime", "ttl", "scope", "naming"} {
		if _, ok := body[k]; ok {
			t.Fatalf("unset options must not add %q", k)
		}
	}
}

func TestApplyAllocateOptionsSetsFields(t *testing.T) {
	body := map[string]interface{}{}
	applyAllocateOptions(body, AllocateOptions{
		Lifetime:   LifetimeEphemeral,
		TTLSeconds: 300,
		Scope:      ScopeIdentity,
		Naming:     NamingStable,
	})
	want := map[string]interface{}{
		"lifetime": "ephemeral",
		"ttl":      300,
		"scope":    "identity",
		"naming":   "stable",
	}
	for k, v := range want {
		if body[k] != v {
			t.Fatalf("body[%q] = %v, want %v", k, body[k], v)
		}
	}
}

// ttl is meaningful only for an ephemeral lifetime; a permanent lifetime (or an
// unset one) must never put ttl on the wire.
func TestApplyAllocateOptionsTTLOnlyWhenEphemeral(t *testing.T) {
	permanent := map[string]interface{}{}
	applyAllocateOptions(permanent, AllocateOptions{Lifetime: LifetimePermanent, TTLSeconds: 300})
	if _, ok := permanent["ttl"]; ok {
		t.Fatal("ttl must be omitted for a permanent lifetime")
	}
	if permanent["lifetime"] != "permanent" {
		t.Fatalf("lifetime = %v, want permanent", permanent["lifetime"])
	}

	// ephemeral but zero ttl → still omitted (nothing meaningful to request).
	zero := map[string]interface{}{}
	applyAllocateOptions(zero, AllocateOptions{Lifetime: LifetimeEphemeral})
	if _, ok := zero["ttl"]; ok {
		t.Fatal("ttl must be omitted when TTLSeconds is zero")
	}
}

// Mirrors TestCanonicalBodyStable: the signed encoding is deterministic with the
// new fields present, and those fields are part of the signed bytes.
func TestCanonicalBodyStableWithOptions(t *testing.T) {
	body := map[string]interface{}{
		"v": JSONVersion, "raid": "ERAID", "intent": "serve-didwebs-artifacts",
		"signed_by": "EEnrollment", "ttl_hint": "persistent",
	}
	applyAllocateOptions(body, AllocateOptions{
		Lifetime:   LifetimeEphemeral,
		TTLSeconds: 600,
		Scope:      ScopeIdentity,
		Naming:     NamingStable,
	})

	a, err := canonicalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical unstable: %s vs %s", a, b)
	}
	for _, sub := range []string{`"lifetime":"ephemeral"`, `"ttl":600`, `"scope":"identity"`, `"naming":"stable"`} {
		if !strings.Contains(string(a), sub) {
			t.Fatalf("canonical body missing %s: %s", sub, a)
		}
	}
}
