package relay_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

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

const callerLabel = "q7Zk2mV9xW4pLr8sTn3uYa"

// A client pointed at the relay's connect host is handed addresses at the
// caller-facing host, as the real relay does. The descriptor's caller host is
// what Allocate holds the address to, so discovery and Allocate agree.
func TestAClientPointedAtTheConnectHostIsGivenAddressesAtTheCallerHost(t *testing.T) {
	desc := func() *relay.ServiceDescriptor {
		return &relay.ServiceDescriptor{Service: "relay.example", ConnectHost: "connect.relay.example",
			CallerHost:     "relay.example",
			TunnelEndpoint: "wss://connect.relay.example/tunnel",
			Endpoints:      map[string]string{relay.OpAllocate: "https://connect.relay.example/allocate"}}
	}
	d := desc()
	if err := relay.CheckConnectHost("https://connect.relay.example", d); err != nil {
		t.Fatalf("discovery refused a client pointed at the connect host: %v", err)
	}
	c := allocatingClient("https://relay.example/"+callerLabel, callerLabel)
	c.BaseURL = "https://connect.relay.example"
	c.Descriptor = d
	if l, _, err := c.Allocate(context.Background(), "Eaid", "commitment"); err != nil || l != callerLabel {
		t.Fatalf("Allocate refused an address at the descriptor's caller host: %v", err)
	}
	// The connect host is not where callers are: an address there is refused.
	c = allocatingClient("https://connect.relay.example/"+callerLabel, callerLabel)
	c.BaseURL = "https://connect.relay.example"
	c.Descriptor = desc()
	if _, _, err := c.Allocate(context.Background(), "Eaid", "commitment"); err == nil {
		t.Fatal("Allocate accepted an address at the connect host, not the caller host")
	}
}

// A descriptor that names a caller host outside the relay's name, as one
// rewritten by a proxy would, is refused at discovery; and Allocate holds an
// address to the caller host the descriptor names, not to one it was not given.
func TestAForeignCallerHostIsRefused(t *testing.T) {
	d := &relay.ServiceDescriptor{Service: "relay.example", ConnectHost: "relay.example", CallerHost: "other.example",
		TunnelEndpoint: "wss://relay.example/tunnel",
		Endpoints:      map[string]string{relay.OpAllocate: "https://relay.example/allocate"}}
	if err := relay.CheckConnectHost("https://relay.example", d); err == nil ||
		!strings.Contains(err.Error(), "caller host") {
		t.Fatalf("a foreign caller host was accepted: %v", err)
	}
	c := allocatingClient("https://relay.example/"+callerLabel, callerLabel)
	c.Descriptor.CallerHost = "other.example"
	if _, _, err := c.Allocate(context.Background(), "Eaid", "commitment"); err == nil {
		t.Fatal("Allocate accepted an address away from the descriptor's caller host")
	}
}

// The caller host crosses the wire as "caller_host". A client pointed at the
// connect host reads the descriptor the real relay serves, with the apex as the
// caller host, and holds Allocate to it.
func TestFetchDescriptorCarriesTheCallerHostThatDiffersFromTheBase(t *testing.T) {
	c := relay.NewClient("https://connect.relay.example", stubSigner{})
	c.HTTPClient = &http.Client{Transport: answerRoundTripper(func(r *http.Request) string {
		if r.URL.Path == "/.well-known/url-relay-service.json" {
			return `{"protocol":"` + relayproto.ProtocolVersion + `","service":"relay.example","connect_host":"connect.relay.example",` +
				`"caller_host":"relay.example","tunnel_endpoint":"wss://connect.relay.example/tunnel",` +
				`"endpoints":{"` + relay.OpAllocate + `":"https://connect.relay.example/allocate"}}`
		}
		return `{"allocation":"` + callerLabel + `","public_url":"https://relay.example/` + callerLabel + `"}`
	})}
	d, err := c.FetchDescriptor(context.Background())
	if err != nil {
		t.Fatalf("a descriptor with the apex as caller host was refused: %v", err)
	}
	if d.CallerHost != "relay.example" {
		t.Fatalf("caller_host did not cross the wire: got %q", d.CallerHost)
	}
	if l, _, err := c.Allocate(context.Background(), "Eaid", "commitment"); err != nil || l != callerLabel {
		t.Fatalf("Allocate did not hold the address to the fetched caller host: %v", err)
	}
}

// A connect host's caller host is its immediate parent and no other ancestor,
// and only when the client was pointed at the connect host.
func TestOnlyTheConnectHostsImmediateParentIsAcceptedAsCallerHost(t *testing.T) {
	check := func(base, connect, caller string) error {
		d := &relay.ServiceDescriptor{Service: "relay.example.com", ConnectHost: connect, CallerHost: caller,
			TunnelEndpoint: "wss://" + connect + "/tunnel",
			Endpoints:      map[string]string{relay.OpAllocate: "https://" + connect + "/allocate"}}
		return relay.CheckConnectHost(base, d)
	}
	if err := check("https://connect.relay.example.com", "connect.relay.example.com", "relay.example.com"); err != nil {
		t.Fatalf("the immediate parent was refused: %v", err)
	}
	for _, caller := range []string{"example.com", "com"} {
		if err := check("https://connect.relay.example.com", "connect.relay.example.com", caller); err == nil {
			t.Fatalf("the ancestor %s was accepted as caller host", caller)
		}
	}
	// Pointed at the connect host but with none named, the parent is not allowed.
	d := &relay.ServiceDescriptor{Service: "x", CallerHost: "relay.example.com",
		TunnelEndpoint: "wss://connect.relay.example.com/tunnel",
		Endpoints:      map[string]string{relay.OpAllocate: "https://connect.relay.example.com/allocate"}}
	if err := relay.CheckConnectHost("https://connect.relay.example.com", d); err == nil {
		t.Fatal("the parent was accepted with no connect host named")
	}
}

// The scheme's default port is the same host as no port.
func TestAllocateTreatsTheDefaultPortAsNoPort(t *testing.T) {
	for _, public := range []string{"https://relay.example:443/" + callerLabel, "https://relay.example/" + callerLabel} {
		if _, _, err := allocatingClient(public, callerLabel).Allocate(context.Background(), "Eaid", "commitment"); err != nil {
			t.Fatalf("%s was refused: %v", public, err)
		}
	}
	c := allocatingClient("https://relay.example/"+callerLabel, callerLabel)
	c.Descriptor.CallerHost = "relay.example:443"
	if _, _, err := c.Allocate(context.Background(), "Eaid", "commitment"); err != nil {
		t.Fatalf("a caller host with the default port was refused: %v", err)
	}
	if _, _, err := allocatingClient("https://relay.example:8443/"+callerLabel, callerLabel).Allocate(context.Background(), "Eaid", "commitment"); err == nil {
		t.Fatal("a non-default port was accepted")
	}
}
