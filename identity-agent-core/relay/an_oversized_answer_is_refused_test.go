package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/internal/boundedread"
)

// A relay's answer over maxAnswer is refused, whether it is the descriptor or the
// answer to a control request, even when its first part is a valid document.
func TestARelayAnswerOverTheLimitIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"x":"` + strings.Repeat("a", maxAnswer) + `"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	if _, err := c.FetchDescriptor(context.Background()); !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("descriptor: %v", err)
	}
	c.Descriptor = &ServiceDescriptor{Service: "r", Endpoints: map[string]string{OpReleaseDomain: srv.URL}}
	c.Signer = signerFunc{}
	if err := c.ReleaseDomain(context.Background(), "E1", "example.org"); !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("control: %v", err)
	}
}

type signerFunc struct{}

func (signerFunc) SignCanonical(string, map[string]interface{}) (string, error) { return "sig", nil }
