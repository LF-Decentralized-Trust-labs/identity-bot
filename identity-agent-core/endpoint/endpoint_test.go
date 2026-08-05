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
