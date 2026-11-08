package relay_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"identity-agent-core/relay"
)

type answerRoundTripper func(*http.Request) string

func (f answerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r,
		Body: io.NopCloser(bytes.NewReader([]byte(f(r))))}, nil
}

type stubSigner struct{}

func (stubSigner) SignCanonical(string, map[string]interface{}) (string, error) { return "sig", nil }

func allocatingClient(public, label string) *relay.Client {
	c := relay.NewClient("https://relay.example", stubSigner{})
	c.Descriptor = &relay.ServiceDescriptor{Service: "relay.example", ConnectHost: "relay.example",
		Endpoints: map[string]string{relay.OpAllocate: "https://relay.example/allocate"}}
	c.HTTPClient = &http.Client{Transport: answerRoundTripper(func(*http.Request) string {
		return `{"allocation":"` + label + `","public_url":"` + public + `"}`
	})}
	return c
}

// Allocate itself must refuse an address that shows the relationship in the
// handshake: one with the label in the host, or on a host other than the
// relay's own (a host per identity such as https://x7k.relay/<label>).
func TestAllocateRefusesAnAddressThatIsNotAPathAtTheRelaysOwnHost(t *testing.T) {
	const label = "q7Zk2mV9xW4pLr8sTn3uYa"
	for name, public := range map[string]string{
		"label in host": "https://" + label + ".relay.example/" + label,
		"another host":  "https://x7k.relay.example/" + label,
		"another relay": "https://other.example/" + label,
		"another port":  "https://relay.example:8443/" + label,
		"not a path":    "https://relay.example/other",
		"not https":     "http://relay.example/" + label,
	} {
		t.Run(name, func(t *testing.T) {
			if l, u, err := allocatingClient(public, label).Allocate(context.Background(), "Eaid", "commitment"); err == nil {
				t.Fatalf("accepted %s as %s %s", public, l, u)
			}
		})
	}
	l, u, err := allocatingClient("https://RELAY.example/"+label, label).Allocate(context.Background(), "Eaid", "commitment")
	if err != nil || l != label || !strings.HasSuffix(u, "/"+label) {
		t.Fatalf("a path at the relay's own host was refused: %v %q", err, u)
	}
}
