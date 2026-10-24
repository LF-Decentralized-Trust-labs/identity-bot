package server

import (
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

// A production build takes nothing as measured that was not measured, so an
// unvouched controller stays out of every raised action exactly as before.
func TestAProductionBuildTakesNothingAsMeasured(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("nothing vouched"), false, false, false, now)
	if got.Measured {
		t.Fatalf("a production build treated an unmeasured controller as measured: %+v", got)
	}
	if ok, _ := mayThisControllerDoThis("POST", "/api/mcp/agents", got, now); ok {
		t.Fatal("a production build let an unmeasured controller create an AI agent")
	}
}

// The stand-in opens the verified actions — creating an AI agent among them —
// and nothing raised to high.
func TestADevelopmentBuildOpensVerifiedButNotHigh(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("nothing vouched"), false, true, false, now)
	if got.Provider != developmentBuildProvider {
		t.Fatalf("the stand-in is not labelled as one: %q", got.Provider)
	}
	for _, route := range []string{"/api/mcp/agents", "/api/mcp/tokens"} {
		if ok, why := mayThisControllerDoThis("POST", route, got, now); !ok {
			t.Fatalf("a development build refused POST %s: %s", route, why)
		}
	}
	if ok, _ := mayThisControllerDoThis(
		"PUT", "/api/mcp/agents/{id}/capabilities", got, now); !ok {
		t.Fatal("a development build refused re-issuing an AI agent's grant")
	}
	for _, route := range []string{"/api/rotation", "/api/backup/export", "/api/keystore/root-seed"} {
		if ok, _ := mayThisControllerDoThis("POST", route, got, now); ok {
			t.Fatalf("a development build opened POST %s, which is raised to high", route)
		}
	}
	if ok, _ := mayThisControllerDoThis("POST", "/api/controllers", got, now); ok {
		t.Fatal("a development build opened enrolling a controller, which no level opens")
	}
}

// A person who was checked and fell short was not checked "by default": the
// real, lower answer stands.
func TestADevelopmentBuildKeepsAMeasuredLowerLevel(t *testing.T) {
	now := time.Now().UTC()
	measured := authprovider.Result{
		Level: authprovider.LevelBasic, Measured: true, At: now, Provider: "root-identity-device",
	}
	got := whatThisBuildTakesAsMeasured(measured, true, true, false, now)
	if got != measured {
		t.Fatalf("a development build replaced a real measurement: %+v", got)
	}
	if ok, _ := mayThisControllerDoThis("POST", "/api/mcp/agents", got, now); ok {
		t.Fatal("a measured basic level created an AI agent")
	}
}

// A statement that was offered and did not hold up — unvouched, or forged — is
// not raised by the stand-in: it was an attempt, not an absence.
func TestADevelopmentBuildDoesNotRaiseARefusedStatement(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("not vouched for by the device that holds the key"), true, true, false, now)
	if got.Measured {
		t.Fatalf("a refused statement was taken as verified: %+v", got)
	}
}

// A development build that anything outside this computer can reach takes
// nothing as measured: every machine holding a grant there would otherwise be
// able to issue credentials, mint tokens and create AI agents for the identity.
func TestADevelopmentBuildReachableFromOutsideTakesNothingAsMeasured(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("nothing vouched"), false, true, true, now)
	if got.Measured {
		t.Fatalf("a reachable development build vouched for a controller: %+v", got)
	}
	for _, route := range []string{"/api/mcp/agents", "/api/mcp/tokens"} {
		if ok, _ := mayThisControllerDoThis("POST", route, got, now); ok {
			t.Fatalf("a reachable development build let an unmeasured controller POST %s", route)
		}
	}
}

// Every way this agent can be reached from elsewhere counts, including the
// ones that are only intended so far — a relay configured but not connected,
// a tunnel still starting — and only loopback with nothing published does not.
func TestWhatCountsAsReachableFromOutside(t *testing.T) {
	cases := []struct {
		name string
		h    howThisAgentIsReached
		want bool
	}{
		{"loopback only, nothing published", howThisAgentIsReached{PublishedSource: "localhost"}, false},
		{"not yet started", howThisAgentIsReached{}, false},
		{"listening on loopback explicitly", howThisAgentIsReached{ListensOn: "127.0.0.1"}, false},
		{"a sealed instance", howThisAgentIsReached{SealedInstance: true}, true},
		{"listening on every interface", howThisAgentIsReached{ListensOn: "0.0.0.0"}, true},
		{"listening on a LAN address", howThisAgentIsReached{ListensOn: "192.168.0.10"}, true},
		{"holding a relay address while disconnected", howThisAgentIsReached{HoldsRelay: true}, true},
		{"a relay configured, not yet up", howThisAgentIsReached{RelayConfigured: true}, true},
		{"a tunnel", howThisAgentIsReached{Tunnel: true}, true},
		{"PUBLIC_URL set", howThisAgentIsReached{PublicURL: "https://agent.example"}, true},
		{"an override address", howThisAgentIsReached{PublishedSource: "override"}, true},
		{"an address a proxy reported", howThisAgentIsReached{PublishedSource: "observed:proxy"}, true},
		{"a relay address published", howThisAgentIsReached{PublishedSource: "relay:example"}, true},
	}
	for _, c := range cases {
		got, why := whoCanReachThisAgent(c.h)
		if got != c.want {
			t.Errorf("%s: reachable = %v, want %v", c.name, got, c.want)
		}
		if got && why == "" {
			t.Errorf("%s: reachable with no reason given", c.name)
		}
	}
}

// The facts are read from the running agent, not assumed: a configured relay
// operator or a PUBLIC_URL on a real server makes it reachable.
func TestTheRunningAgentReportsHowItIsReached(t *testing.T) {
	s := &CoreServer{}
	if got, _ := whoCanReachThisAgent(s.howThisAgentIsReachedNow()); got {
		t.Fatal("a bare agent with nothing configured was taken as reachable from outside")
	}
	t.Setenv("PUBLIC_URL", "https://agent.example")
	if got, _ := whoCanReachThisAgent(s.howThisAgentIsReachedNow()); !got {
		t.Fatal("an agent publishing PUBLIC_URL was taken as reachable only from this computer")
	}
}
