package endpoint

import (
	"strings"
	"testing"
)

// Where an agent says it can be reached.
//
// This is not a display string. It is composed into the OOBI an agent publishes,
// so a counterparty resolving that identity goes wherever this says — and an
// agent that answers with an address nobody outside can reach is an agent nobody
// can pair with, for reasons that show up as somebody else's connection error.

// An agent behind a reverse proxy cannot work its own public address out. It
// sees a request arrive on loopback; the name and scheme the person actually
// used are known only to the proxy. So the proxy tells it — and the answer has
// to be the one it publishes, or being told achieves nothing.
//
// It was told and then ignored: the value was stored by SetObservedURL and never
// read when resolving, so an agent reachable at a public address published a
// LAN one instead.
func TestTheAddressAProxyReportedIsTheOneWePublish(t *testing.T) {
	es := New(nil, 5050)
	before := es.CurrentURL()

	es.SetObservedURL("https://agent.example.net/abc")

	if got := es.CurrentURL(); got != "https://agent.example.net/abc" {
		t.Fatalf("published %q after being told the real address (was %q) — a counterparty resolving this goes nowhere",
			got, before)
	}
	if got := es.Source(); got != "observed:proxy" {
		t.Errorf("source is %q, want observed:proxy", got)
	}
}

// A trailing slash is not a different address, and leaving it on produces a
// double slash in every OOBI composed from it.
func TestATrailingSlashIsNotPartOfTheAddress(t *testing.T) {
	es := New(nil, 5050)
	es.SetObservedURL("https://agent.example.net/abc/")
	if strings.HasSuffix(es.CurrentURL(), "/") {
		t.Errorf("kept a trailing slash: %q", es.CurrentURL())
	}
}

// An explicit override is somebody stating the answer outright, and it wins over
// an address inferred from a request — including a correctly inferred one.
func TestSomebodyStatingTheAddressOutrightWins(t *testing.T) {
	es := New(nil, 5050)
	es.SetObservedURL("https://observed.example")
	es.SetOverrideURL("https://stated.example")

	if got := es.CurrentURL(); got != "https://stated.example" {
		t.Errorf("published %q, want the stated address", got)
	}
	if got := es.Source(); got != "override" {
		t.Errorf("source is %q, want override", got)
	}
}

// Nothing observed means nothing changes: an agent that is not behind a proxy
// keeps working its address out exactly as it did before.
func TestAnAgentWithNoProxyIsUnaffected(t *testing.T) {
	es := New(nil, 5050)
	// Refresh, because that is what startup does — the constructor loads any
	// stored address but does not resolve one.
	es.Refresh()

	if es.Source() == "observed:proxy" {
		t.Fatalf("an agent nobody told anything claims a proxy told it: %q", es.CurrentURL())
	}
	if es.CurrentURL() == "" {
		t.Error("an agent with no proxy worked out no address at all")
	}
}

// With no tunnel, no relay and no direct-ingress hatch, the agent binds loopback
// only — so it must advertise localhost, NOT the LAN IP.
//
// Ranking the LAN IP first was a silent break: the address went into the OOBI and
// pairing QR, but nothing was listening there, so a counterparty resolving it hit
// connection-refused. The address published has to match where the agent actually
// answers.
func TestALoopbackOnlyAgentAdvertisesLocalhostNotADeadLANIP(t *testing.T) {
	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "")
	t.Setenv("PUBLIC_URL", "")

	es := New(nil, 5050)
	url, source := es.resolve()

	if source != "localhost" {
		t.Fatalf("a loopback-only agent published source %q (%q) — a counterparty resolving a LAN IP nothing listens on gets connection-refused",
			source, url)
	}
	if url != "http://localhost:5050" {
		t.Errorf("published %q, want http://localhost:5050", url)
	}
}

// A loopback host in the escape hatch is still loopback: it does not make the LAN
// IP reachable, so the agent still advertises localhost.
func TestALoopbackIngressHatchStillAdvertisesLocalhost(t *testing.T) {
	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "127.0.0.1")
	t.Setenv("PUBLIC_URL", "")

	es := New(nil, 5050)
	if _, source := es.resolve(); source != "localhost" {
		t.Fatalf("a hatch bound to loopback published source %q, want localhost", source)
	}
}

// When the direct-ingress hatch binds the surface to a non-loopback host
// (0.0.0.0 here), the LAN IP is genuinely reachable, so it is advertised.
//
// Guarded on there actually being a LAN interface: a host with none correctly
// falls back to localhost, and asserting a LAN IP there would fail for the right
// reason in the wrong test.
func TestAReachableIngressHatchAdvertisesTheLANIP(t *testing.T) {
	if detectLocalIP() == "" {
		t.Skip("no non-loopback interface on this host; the LAN-IP branch cannot be exercised")
	}
	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "0.0.0.0")
	t.Setenv("PUBLIC_URL", "")

	es := New(nil, 5050)
	url, source := es.resolve()

	if !strings.HasPrefix(source, "local:") {
		t.Fatalf("with the surface bound off-box the agent published source %q (%q) — the reachable LAN IP should win over localhost",
			source, url)
	}
	if want := "http://" + detectLocalIP() + ":5050"; url != want {
		t.Errorf("published %q, want %q", url, want)
	}
}

// The source has to actually become "observed:proxy", because that string is
// what the request middleware checks to decide it has already learned the
// address and can stop looking.
//
// While resolve() ignored observedURL the source could never take that value, so
// the check never matched and the address was re-learned on every single request
// — an agent's published address would move to wherever the most recent caller
// said, which is precisely what taking the first answer exists to prevent.
func TestTheSourceIsWhatMakesFirstAnswerWinsWork(t *testing.T) {
	es := New(nil, 5050)
	es.SetObservedURL("https://first.example")
	if es.Source() != "observed:proxy" {
		t.Fatalf("source is %q, so the middleware would never see that it had already learned an address", es.Source())
	}
}
