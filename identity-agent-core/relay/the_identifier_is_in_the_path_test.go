package relay_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/relay"
	"identity-agent-core/relay/relaytest"
)

// The host name is in clear in every TLS handshake, so a relationship's
// identifier must never be in it: two relationships at one relay show the same
// name on the wire, and only the path, inside the encryption, tells them apart.
func TestARelationshipsIdentifierNeverAppearsInTheHostName(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	var labels []string
	var hosts []string
	for i := 0; i < 2; i++ {
		e := newEnrolment(t)
		m := managerFor(t, rl, e, relayproto.ModePrivate)
		if err := m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer m.Stop()
		waitFor(t, "the relay address", func() bool { return m.URL() != "" })
		a := m.Allocation()
		u, err := url.Parse(a.URL)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(u.Hostname()), strings.ToLower(a.Label)) {
			t.Fatalf("the identifier %s is in the host name of %s", a.Label, a.URL)
		}
		if !strings.HasPrefix(u.Path, "/"+a.Label) {
			t.Fatalf("the identifier %s is not in the path of %s", a.Label, a.URL)
		}
		labels = append(labels, a.Label)
		hosts = append(hosts, u.Host)

		// Reached by a host name (a real one has a name, not an IP, so the
		// handshake carries it), the identifier is still not on the wire.
		named := strings.Replace(a.URL, u.Hostname(), "relay.test", 1)
		if code, body := get(t, rl.Caller(), "GET", named+"/oobi/"+e.aid, ""); code != 200 {
			t.Fatalf("not reachable by name: %d %q", code, body)
		}
	}
	if labels[0] == labels[1] || hosts[0] != hosts[1] {
		t.Fatalf("two relationships must differ in the path only: %v at %v", labels, hosts)
	}
	seen := rl.ServerNames()
	if len(seen) == 0 {
		t.Fatal("the test relay saw no handshake name")
	}
	for _, sni := range seen {
		for _, l := range labels {
			if strings.Contains(strings.ToLower(sni), strings.ToLower(l)) {
				t.Fatalf("the identifier %s was sent in clear as the handshake name %q", l, sni)
			}
		}
	}
}

// A relay that answers an allocation with a host of its own for the
// relationship is refused, so the Identity Agent never holds an address that
// shows the relationship in the handshake.
func TestARelayThatNamesTheRelationshipInTheHostIsRefused(t *testing.T) {
	label := relayproto.NewAllocationToken()
	for _, bad := range []string{
		"https://" + label + ".relay.example",
		"https://" + label + ".relay.example/" + label,
		"https://relay.example/other",
		"http://relay.example/" + label,
		"https://relay.example/" + label + "?x=1",
	} {
		if relayproto.CheckPrivateURL(bad, label) == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	for _, good := range []string{"https://relay.example/" + label, "https://relay.example:8443/" + label + "/"} {
		if err := relayproto.CheckPrivateURL(good, label); err != nil {
			t.Errorf("%s was refused: %v", good, err)
		}
	}
}

// An address held in the retired subdomain form keeps working, unchanged and
// at the same URL, for as long as the relay serves it (ADR-048 §8, transition).
func TestAnOldSubdomainAddressStillResolvesDuringTheTransition(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	rl.LegacySubdomains = true
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	made := m.Allocation()
	m.Stop()

	// The same address as an older Identity Agent recorded it.
	u, _ := url.Parse(made.URL)
	old := *made
	old.URL = "https://" + made.Label + "." + u.Host

	again := managerFor(t, rl, e, relayproto.ModePrivate)
	again.Remember([]relay.Allocation{old})
	if err := again.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer again.Stop()
	waitFor(t, "the relay address", func() bool { return again.URL() != "" })
	if again.URL() != old.URL {
		t.Fatalf("the old address was replaced: %s became %s", old.URL, again.URL())
	}
	if code, body := get(t, rl.Caller(), "GET", old.URL+"/oobi/"+e.aid, ""); code != 200 || body != "oobi of "+e.aid {
		t.Fatalf("the old subdomain no longer resolves: %d %q", code, body)
	}
	// And the same address in its new form reaches the same Identity Agent.
	if code, _ := get(t, rl.Caller(), "GET", made.URL+"/oobi/"+e.aid, ""); code != 200 {
		t.Fatalf("the path form does not resolve: %d", code)
	}
}
