package relay

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"
)

// A relay-forwarded request must never look like the box's genuinely-local
// owner. The box treats a loopback request with no forwarding marker as the
// owner (server.isLocalOwnerRequest); a relay frame reaches the box over
// loopback too, so the relay stamps X-IA-Via-Ingress on the forwarded request.
// Without it, anyone who learned the relay URL would be the owner, no signature.
func TestForwardRequestStampsIngressMarker(t *testing.T) {
	a := &TunnelAgent{LocalBase: "http://127.0.0.1:5050"}

	req := RequestFrame{
		Method:  "POST",
		Path:    "/api/controllers",
		Headers: map[string]string{"Content-Type": "application/json"},
	}
	httpReq, err := a.newForwardRequest(req)
	if err != nil {
		t.Fatalf("newForwardRequest: %v", err)
	}
	if got := httpReq.Header.Get("X-IA-Via-Ingress"); got != "relay" {
		t.Fatalf("X-IA-Via-Ingress = %q, want %q", got, "relay")
	}
	if got := httpReq.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("client header not forwarded: Content-Type = %q", got)
	}

	// A client cannot preempt the marker to look local: the relay sets it after
	// the client's headers are applied, so a spoofed value is overridden.
	req.Headers["X-IA-Via-Ingress"] = "spoofed-local"
	httpReq2, err := a.newForwardRequest(req)
	if err != nil {
		t.Fatalf("newForwardRequest: %v", err)
	}
	if got := httpReq2.Header.Get("X-IA-Via-Ingress"); got != "relay" {
		t.Fatalf("client spoofed the marker: X-IA-Via-Ingress = %q, want %q", got, "relay")
	}
}

// The forwarded request must carry the inbound body, or every signed POST over
// the relay (a controller grant, a rotation, any owner/controller action) fails
// signature verification because the body it signed over arrived empty.
func TestForwardRequestCarriesTheBody(t *testing.T) {
	a := &TunnelAgent{LocalBase: "http://127.0.0.1:5050"}
	payload := []byte(`{"controller_aid":"BTheLaptop","grade":"enrolled"}`)
	b64 := base64.RawURLEncoding.EncodeToString(payload)

	req := RequestFrame{Method: "POST", Path: "/api/controllers", BodyB64: &b64}
	httpReq, err := a.newForwardRequest(req)
	if err != nil {
		t.Fatalf("newForwardRequest: %v", err)
	}
	if httpReq.Body == nil {
		t.Fatal("forwarded request has no body")
	}
	got, _ := io.ReadAll(httpReq.Body)
	if !bytes.Equal(got, payload) {
		t.Fatalf("forwarded body = %q, want %q", got, payload)
	}

	// No body frame → no body, not an error.
	bare, err := a.newForwardRequest(RequestFrame{Method: "GET", Path: "/api/agents"})
	if err != nil {
		t.Fatalf("newForwardRequest (no body): %v", err)
	}
	if bare.Body != nil && bare.ContentLength > 0 {
		t.Fatalf("bodyless request got a body of %d bytes", bare.ContentLength)
	}
}
